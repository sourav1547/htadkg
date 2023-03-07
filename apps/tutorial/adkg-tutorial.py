"""
ADKG tutorial.

Instructions:
   run this with
```
sh scripts/launch-tmuxlocal.sh apps/tutorial/adkg-tutorial.py conf/adkg/local
```
"""
from adkg.config import HbmpcConfig
from adkg.adkg import ADKG
from adkg.poly_commit_hybrid import PolyCommitHybrid
import asyncio
import time
import logging
import uvloop
import numpy as np

# from pypairing import ZR, G1, blsmultiexp as multiexp, dotprod
from pypairing import Curve25519ZR as ZR, Curve25519G as G1, curve25519multiexp as multiexp, curve25519dotprod as dotprod

logger = logging.getLogger("benchmark_logger")
# logger.setLevel(logging.ERROR)
# Uncomment this when you want logs from this file.
logger.setLevel(logging.NOTSET)

def get_avss_params(n, G1):
    g, h = G1.hash(b'g'), G1.hash(b'h') 
    public_keys, private_keys = [None] * n, [None] * n
    for i in range(n):
        private_keys[i] = ZR.hash(str(i).encode())
        public_keys[i] = pow(g, private_keys[i])
    return g, h, public_keys, private_keys

def gen_vector(t, deg, n):
    coeff_1 = np.array([[ZR(i+1)**j for j in range(t+1)] for i in range(n)])
    coeff_2 = np.array([[ZR(i+1)**j for j in range(t+1, deg+1)] for i in range(n)])
    hm_1 = np.array([[ZR(i+1)**j for j in range(n)] for i in range(t+1)])
    hm_2 = np.array([[ZR(i+1)**j for j in range(n)] for i in range(deg-t)])
    rm_1 = np.matmul(coeff_1, hm_1)
    rm_2 = np.matmul(coeff_2, hm_2)

    return (rm_1.tolist(), rm_2.tolist())

async def _run(peers, n, t, k, my_id, start_time):
    g, h, pks, sks = get_avss_params(n, G1)
    pc = PolyCommitHybrid(g, h, ZR, multiexp)

    deg = k
    mat1, mat2 = gen_vector(t, deg, n)
    deg = 2*t
    curve_params = (ZR, G1, multiexp, dotprod)
    
    print(f"--"*50)
    logging.info(f"ADKG Experiment with n:{n}, t:{t}, deg:{deg}")

    from adkg.ipc import ProcessProgramRunner
    async with ProcessProgramRunner(peers, n, t, my_id) as runner:
        send, recv = runner.get_send_recv("ADKG")
        logging.debug(f"Start time: {(start_time)}, diff {(start_time-int(time.time()))}")
        benchmark_logger = logging.LoggerAdapter(
           logging.getLogger("benchmark_logger"), {"node_id": my_id}
        )
 
        with ADKG(pks, sks[my_id], g, h, n, t, deg, my_id, send, recv, pc, curve_params, (mat1, mat2)) as adkg:
            while True:
                if time.time() > start_time:
                    break
                time.sleep(0.1)
            
            begin_time = time.time()
            adkg_task = asyncio.create_task(adkg.run_adkg(begin_time))
            # await adkg.output_queue.get()
            await adkg_task
            end_time = time.time()
            adkg_time = end_time-begin_time
            benchmark_logger.info("ADKG time: %f", adkg_time)
            try:
                adkg.kill()
                adkg_task.cancel()
            except:
                logging.debug("Processed killed!")
        bytes_sent = runner.node_communicator.bytes_sent
        logging.info(f"Total data sent: {round(bytes_sent/2**20,3)} Megabytes")
        all_bws = process_bw(runner.node_communicator.bytes_count)
        for k,v in all_bws.items():
            logging.info(f"Data Sent during {k} phase is {round((100*v)/bytes_sent,3)}%")
        print(f"--"*50)
        

def process_bw(raw):
    return {'ACSS': raw['A'], 'AGREEMENT': raw['A']+raw['B'], 'RAND EX':raw['P'], 'KEY DERIV': raw['K']}



if __name__ == "__main__":
    from adkg.config import HbmpcConfig
    HbmpcConfig.load_config()
    
    loop = uvloop.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(
            _run(
                HbmpcConfig.peers,
                HbmpcConfig.N,
                HbmpcConfig.t,
                HbmpcConfig.k,
                HbmpcConfig.my_id,
                HbmpcConfig.time,
            )
        )
    finally:
        loop.close()