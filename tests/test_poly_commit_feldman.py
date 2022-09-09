from pytest import mark
from pypairing import ZR, G1
from adkg.polynomial import polynomials_over
from adkg.poly_commit_feldman import PolyCommitFeldman

@mark.parametrize(
    "t, deg, n",
    [
        (5, 10, 16),
        (10, 21, 32),
        (21, 42, 64),
        (42, 85, 128),
    ])
def test_benchmark_poly_commit_feldman(benchmark, t, deg, n):
    crs = G1.rand()
    pc = PolyCommitFeldman(crs)
    phi = polynomials_over(ZR).random(t)
    c = pc.commit(phi)
    benchmark(_verify_commit, pc, c, phi)

def _verify_commit(pc, c, phi):
    pc.verify_eval(c, 3, phi(3))

def test_pc_const():
    t = 42
    crs = G1.rand()
    pc = PolyCommitFeldman(crs)
    phi = polynomials_over(ZR).random(t)
    c = pc.commit(phi)
    assert pc.verify_eval(c, 3, phi(3))
    assert pc.verify_eval(c, 20, phi(20))
    assert pc.verify_eval(c, 0, phi(0))
    assert not pc.verify_eval(c, 3, phi(4))
    assert not pc.verify_eval(c, 3, ZR.rand())