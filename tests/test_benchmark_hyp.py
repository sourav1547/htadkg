from pytest import mark
from adkg.polynomial import polynomials_over
# from pypairing import Curve25519G as G1, Curve25519ZR as ZR, curve25519multiexp as multiexp, curve25519dotprod as dotprod
from pypairing import G1, ZR, blsmultiexp as multiexp

def get_avss_params(G1):
    g, h = G1.hash(b'g'), G1.hash(b'h') 
    return g, h

@mark.parametrize(
    "t, deg, n",
    [
        (5, 10, 16),
        (10, 21, 32),
        (21, 42, 64),
        (42, 85, 128),
    ])
def test_benchmark_hyp(benchmark, t, deg, n):
    g, h = get_avss_params(G1)
    poly = polynomials_over(ZR)
    poly.clear_cache()

    secret = ZR.rand()
    phi = poly.random(deg, secret)
    evals = [phi(i+1) for i in range(deg)]
    commits = [g**evals[i] for i in range(deg)]
    matrix = [[ZR(i+1)**j for j in range(deg)] for i in range(n)]

    benchmark(_compute_commit, g, h, t, deg, n, commits, matrix)

    # benchmark(_get_dealer_msg, secret, pks, g, t, deg, n, poly)

def _compute_commit(g, h, t, deg, n, commits, matrix):
    output = [multiexp(commits, matrix[i]) for i in range(n)]
    return output