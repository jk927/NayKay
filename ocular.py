from pwn import *
import json
import math
import time

context.log_level = 'error'  # tystar pwntools "Opening connection..."-rader

HOST = "socket.cryptohack.org"
PORT = 13423

BLOCK_SIZE = 16
HEX_CHARS = "0123456789abcdef"          # klartexten är hex, så bara 16 möjliga byten per position
N_ARMS = len(HEX_CHARS)

# --- Oracle-brus (se challange.py) ---
# result = good ^ (rng.random() > 0.4):
#   korrekt gissning (good=True)  -> result True med sannolikhet 0.4
#   fel gissning     (good=False) -> result True med sannolikhet 0.6
# Att hitta rätt byte är alltså "hitta armen med lägst True-frekvens" bland 16.
P_CORRECT = 0.4
P_WRONG = 0.6

# Log-likelihood-steg för den frågade armen (Bayesiansk uppdatering).
# Den gemensamma faktorn för alla andra armar cancellerar i normaliseringen,
# så bara den frågade armens log-posterior ändras med +/- D.
D = math.log(P_WRONG) - math.log(P_CORRECT)   # ~0.405

# --- Budget & stoppkriterium ---
# challange.py tillåter 12_000 frågor per anslutning innan den stänger.
# Vi håller oss under med marginal och stoppar varje position när ledarens
# posterior är säker nog. Tröskel ~0.999 gav bäst lyckandegrad i simulering
# (~94% på EN runda); högre tröskel svälter sena positioner på budget.
GLOBAL_BUDGET = 11_800
POS_CAP = 1_500          # tak per position (nås sällan)
POST_THRESH = 0.999      # stoppa när P(ledare) >= detta

VERBOSE = False

_exp = math.exp


def build_probe(fake_prev, pos, guess, target_block):
    fake_prev[pos] = guess
    return bytes(fake_prev) + target_block


def send_probe(conn, query_ref, probe):
    # Ping-pong: skicka en, läs en. Att pipelinea flera sendline innan recv
    # triggar delayed-ACK/Nagle på serverns svar (~40 ms straff per klump).
    conn.sendline(json.dumps({"option": "unpad", "ct": probe.hex()}).encode())
    query_ref[0] += 1
    return json.loads(conn.recvline())["result"]


def attack_position(conn, query_ref, pos, pad_val, prev_block, target_block,
                    intermediate, budget):
    """Bayesiansk sekventiell sökning efter rätt hex-byte på en position.

    Håller en (onormaliserad) log-posterior per arm. Varje fråga går till den
    nuvarande ledaren; True sänker dess log-posterior med D, False höjer den.
    Stoppar när ledarens normaliserade posterior >= POST_THRESH eller budgeten
    tar slut.
    """
    fake_prev = bytearray(BLOCK_SIZE)
    for i in range(pos + 1, BLOCK_SIZE):
        fake_prev[i] = intermediate[i] ^ pad_val

    # förbered en probe per arm (hex-tecken)
    probes = []
    guesses = []
    for h in HEX_CHARS:
        guess = (ord(h) ^ prev_block[pos]) ^ pad_val
        guesses.append(guess)
        probes.append(build_probe(fake_prev, pos, guess, target_block))

    logp = [0.0] * N_ARMS
    S = float(N_ARMS)        # sum(exp(logp)) = N_ARMS när alla är 0
    used = 0

    def query(i):
        nonlocal used, S
        r = send_probe(conn, query_ref, probes[i])
        used += 1
        S -= _exp(logp[i])
        logp[i] += (-D if r else D)
        S += _exp(logp[i])

    budget = min(budget, POS_CAP)

    # warmup: en fråga per arm för startvärden
    for i in range(N_ARMS):
        if used >= budget:
            break
        query(i)

    # sekventiellt: fråga ledaren tills posteriorn är säker
    while used < budget:
        m = max(logp)
        if (_exp(m) / S) >= POST_THRESH:
            break
        query(logp.index(m))

    winner = logp.index(max(logp))
    # klartext-byte = hex-tecknet; intermediate = guess ^ pad_val
    return guesses[winner] ^ pad_val


def attack_block(conn, query_ref, prev_block, target_block, budget_ref):
    intermediate = bytearray(BLOCK_SIZE)
    plaintext = bytearray(BLOCK_SIZE)

    for pad_val in range(1, BLOCK_SIZE + 1):
        pos = BLOCK_SIZE - pad_val
        remaining = budget_ref[0] - query_ref[0]
        val = attack_position(conn, query_ref, pos, pad_val, prev_block,
                              target_block, intermediate, remaining)
        intermediate[pos] = val
        plaintext[pos] = val ^ prev_block[pos]
        if VERBOSE:
            print(f"  pos={pos}: klartext = {chr(plaintext[pos])!r}  (frågor: {query_ref[0]})")

    return bytes(plaintext)


def try_once():
    query_ref = [0]
    budget_ref = [GLOBAL_BUDGET]
    conn = remote(HOST, PORT)
    conn.recvline()

    def send(data):
        conn.sendline(json.dumps(data).encode())
        return json.loads(conn.recvline())

    try:
        resp = send({"option": "encrypt"})
        ct = bytes.fromhex(resp["ct"])
        iv, c0, c1 = ct[:16], ct[16:32], ct[32:48]

        p1 = attack_block(conn, query_ref, c0, c1, budget_ref)
        p0 = attack_block(conn, query_ref, iv, c0, budget_ref)

        message = (p0 + p1).decode("ascii")
        result = send({"option": "check", "message": message})
        return result, query_ref[0]

    except Exception as e:
        return {"error": f"exception: {e}"}, query_ref[0]

    finally:
        conn.close()


if __name__ == "__main__":
    N_RUNS = 30
    STOP_ON_FLAG = True   # sätt False för att alltid köra alla N_RUNS (ren statistik)

    successes = 0
    query_counts = []
    query_counts_success = []
    query_counts_fail = []
    flag = None

    start_all = time.time()

    for i in range(N_RUNS):
        t0 = time.time()
        result, queries = try_once()
        elapsed = time.time() - t0

        ok = bool(result and 'flag' in result)
        successes += ok
        query_counts.append(queries)
        (query_counts_success if ok else query_counts_fail).append(queries)

        status = "OK" if ok else "FEL"
        print(f"[{i+1}/{N_RUNS}] {status}  frågor={queries}  tid={elapsed:.2f}s")

        if ok and STOP_ON_FLAG:
            flag = result['flag']
            print(f"\n>>> FLAGGA: {flag}")
            break

    total_elapsed = time.time() - start_all

    print("\n--- Statistik ---")
    n = len(query_counts)
    print(f"Lyckade: {successes}/{n} ({successes/n*100:.1f}%)")
    print(f"Frågor (alla):     medel={sum(query_counts)/n:.0f}  "
          f"min={min(query_counts)}  max={max(query_counts)}")
    if query_counts_success:
        print(f"Frågor (lyckade):  medel={sum(query_counts_success)/len(query_counts_success):.0f}")
    if query_counts_fail:
        print(f"Frågor (fel):      medel={sum(query_counts_fail)/len(query_counts_fail):.0f}")
    print(f"Total tid: {total_elapsed:.1f}s ({total_elapsed/n:.2f}s/körning i snitt)")
