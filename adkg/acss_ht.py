import asyncio
from collections import defaultdict
from pickle import dumps, loads
import re
from pypairing import ZR
from adkg.polynomial import polynomials_over
from adkg.symmetric_crypto import SymmetricCrypto
from adkg.utils.misc import wrap_send, subscribe_recv
from adkg.broadcast.optqrbc import optqrbc
from adkg.utils.serilization import Serial


import logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.ERROR)

# Uncomment this when you want logs from this file.
# logger.setLevel(logging.DEBUG)


class HbAVSSMessageType:
    OK = 1
    IMPLICATE = 2
    RECOVERY = 4
    RECOVERY1 = 5
    RECOVERY2 = 6
    KDIBROADCAST = 7

class ACSS_HT:
    #@profile
    def __init__(
            self, public_keys, private_key, g, h, n, t, deg, sc, my_id, send, recv, pc, field=ZR
    ):  # (# noqa: E501)
        self.public_keys, self.private_key = public_keys, private_key
        self.n, self.t, self.deg, self.my_id = n, t, deg, my_id
        self.g, self.h = g, h 
        self.sc = sc 
        self.poly_commit = pc

        self.benchmark_logger = logging.LoggerAdapter(
            logging.getLogger("benchmark_logger"), {"node_id": self.my_id}
        )

        # Create a mechanism to split the `recv` channels based on `tag`
        self.subscribe_recv_task, self.subscribe_recv = subscribe_recv(recv)

        # Create a mechanism to split the `send` channels based on `tag`
        def _send(tag):
            return wrap_send(tag, send)

        self.get_send = _send

        self.acss_status = defaultdict(lambda: True)
        self.field = field
        self.poly = polynomials_over(self.field)
        self.poly.clear_cache()
        self.output_queue = asyncio.Queue()
        self.tagvars = {}
        self.tasks = []

    def __enter__(self):
        return self

    #def __exit__(self, typ, value, traceback):
    def kill(self):
        # self.benchmark_logger.info("ACSS kill called")
        self.subscribe_recv_task.cancel()
        # self.benchmark_logger.info("ACSS recv task cancelled")
        for task in self.tasks:
            task.cancel()
        # self.benchmark_logger.info("ACSS self.tasks cancelled")
        for key in self.tagvars:
            for task in self.tagvars[key]['tasks']:
                task.cancel()
        # self.benchmark_logger.info("ACSS self tagvars canceled")

    
    #@profile
    async def _handle_implication(self, tag, j, idx, j_sk):
        """
        Handle the implication of AVSS.
        Return True if the implication is valid, False otherwise.
        """
        commitments =  self.tagvars[tag]['commitments']
        # discard if PKj ! = g^SKj
        if self.public_keys[j] != pow(self.g, j_sk):
            return False
        # decrypt and verify
        implicate_msg = None #FIXME: IMPORTANT!!
        j_shared_key = pow(self.tagvars[tag]['ephemeral_public_key'], j_sk)

        # Same as the batch size
        secret_count = len(commitments)

        try:
            j_shares, j_witnesses = SymmetricCrypto.decrypt(
                str(j_shared_key).encode(), implicate_msg
            )
        except Exception as e:  # TODO specific exception
            logger.warn("Implicate confirmed, bad encryption:", e)
            return True
        return not self.poly_commit.batch_verify_eval(
            commitments[idx], j + 1, j_shares, j_witnesses, self.t
        )

    def _init_recovery_vars(self, tag):
        self.kdi_broadcast_sent = False
        self.saved_shares = [None] * self.n
        self.saved_shared_actual_length = 0
        self.interpolated = False

    # this function should eventually multicast OK, set self.tagvars[tag]['all_shares_valid'] to True, and set self.tagvars[tag]['shares']
    #@profile
    async def _handle_share_recovery(self, tag, sender=None, avss_msg=[""]):
        send, recv, multicast = self.tagvars[tag]['io']
        if not self.tagvars[tag]['in_share_recovery']:
            return
        if self.tagvars[tag]['all_shares_valid'] and not self.kdi_broadcast_sent:
            logger.debug("[%d] sent_kdi_broadcast", self.my_id)
            kdi = self.tagvars[tag]['shared_key']
            multicast((HbAVSSMessageType.KDIBROADCAST, kdi))
            self.kdi_broadcast_sent = True
        if self.tagvars[tag]['all_shares_valid']:
            return

        if avss_msg[0] == HbAVSSMessageType.KDIBROADCAST:
            logger.debug("[%d] received_kdi_broadcast from sender %d", self.my_id, sender)
            
            # FIXME: IMPORTANT!! read the message from rbc output
            # retrieved_msg = await avid.retrieve(tag, sender)
            retrieved_msg = None
            try:
                j_shares, j_witnesses = SymmetricCrypto.decrypt(
                    str(avss_msg[1]).encode(), retrieved_msg
                )
            except Exception as e:  # TODO: Add specific exception
                logger.debug("Implicate confirmed, bad encryption:", e)
            commitments = self.tagvars[tag]['commitments']
            if (self.poly_commit.batch_verify_eval(commitments,
                                                   sender + 1, j_shares, j_witnesses, self.t)):
                if not self.saved_shares[sender]:
                    self.saved_shared_actual_length += 1
                    self.saved_shares[sender] = j_shares

        # if t+1 in the saved_set, interpolate and sell all OK
        if self.saved_shared_actual_length >= self.t + 1 and not self.interpolated:
            logger.debug("[%d] interpolating", self.my_id)
            # Batch size
            shares = []
            secret_count = len(self.tagvars[tag]['commitments'])
            for i in range(secret_count):
                phi_coords = [
                    (j + 1, self.saved_shares[j][i]) for j in range(self.n) if self.saved_shares[j] is not None
                ]
                shares.append(self.poly.interpolate_at(phi_coords, self.my_id + 1))
            self.tagvars[tag]['all_shares_valid'] = True
            self.tagvars[tag]['shares'] = shares
            self.tagvars[tag]['in_share_recovery'] = False
            self.interpolated = True
            multicast((HbAVSSMessageType.OK, ""))
    
    def decode_proposal(self, proposal):
        # TODO(@sourav): Update this decode proposal function to handle multiple commitments
        # NOTE: Keep the implementation generic so that we can easily swap out the pedersen commit
        g_size = 48
        c_size = 64

        commits, ephkey, dispersal_msg_list = loads(proposal)
        dispersal_msg = dispersal_msg_list[self.my_id]
        
        return (dispersal_msg, commits, ephkey)

        # commit_data = proposal[0:g_size*self.sc*(self.t+1)]
        # commits_raw = Serial.deserialize_gs(commit_data) 
        # commits = [commits_raw[i*g_size*(self.t+1):(i+1)*g_size*(self.t+1)] for i in range(self.sc)]
        
        # ephkey_data = proposal[self.sc*g_size*(self.t+1):self.sc*g_size*(self.t+1)+g_size]
        # ephkey = Serial.deserialize_g(ephkey_data)

        # dispersal_msg_all = loads(proposal[self.sc*g_size*(self.t+1)+g_size:])
        # dispersal_msg = dispersal_msg_all[self.my_id]

        # return (dispersal_msg, commits, ephkey)

    
    def verify_proposal(self, dealer_id, dispersal_msg, commits, ephkey):
        shared_key = pow(ephkey, self.private_key)

        try:
            sharesb = SymmetricCrypto.decrypt(str(shared_key).encode(), dispersal_msg)
        except ValueError as e:  # TODO: more specific exception
            logger.warn(f"Implicate due to failure in decrypting: {e}")
            self.acss_status[dealer_id] = False
            return False

        phis, phis_hat = loads(sharesb)
        # check the feldman commitment of the first secret
        if not self.poly_commit.verify_eval(commits[0], self.my_id + 1, phis[0], None): 
            self.acss_status[dealer_id] = False
            return False
        for i in range(1, self.sc):
            if not self.poly_commit.verify_eval(commits[i], self.my_id + 1, phis[i], phis_hat[i-1]): 
                self.acss_status[dealer_id] = False
                return False
        
        self.acss_status[dealer_id] = True
        return True

    
    #@profile    
    async def _process_avss_msg(self, avss_id, dealer_id, rbc_msg):
        tag = f"{dealer_id}-{avss_id}-B-AVSS"
        send, recv = self.get_send(tag), self.subscribe_recv(tag)
        self._init_recovery_vars(tag)

        def multicast(msg):
            for i in range(self.n):
                send(i, msg)

        self.tagvars[tag]['io'] = [send, recv, multicast]
        self.tagvars[tag]['in_share_recovery'] = False
        dispersal_msg, commits, ephkey = self.decode_proposal(rbc_msg)
        
        ok_set = set()
        implicate_set = set()
        output = False

        self.tagvars[tag]['all_shares_valid'] = self._handle_dealer_msgs(tag, dispersal_msg, (commits, ephkey), dealer_id)

        if self.tagvars[tag]['all_shares_valid']:
            shares = {'msg': self.tagvars[tag]['shares'][0], 'rand':self.tagvars[tag]['shares'][1]}
            commitments = self.tagvars[tag]['commitments']
            self.output_queue.put_nowait((dealer_id, avss_id, shares, commitments))
            output = True
            logger.debug("[%d] Output", self.my_id)
            multicast((HbAVSSMessageType.OK, ""))
        else:
            multicast((HbAVSSMessageType.IMPLICATE, self.private_key))
            implicate_sent = True
            logger.debug("Implicate Sent [%d]", dealer_id)
            self.tagvars[tag]['in_share_recovery'] = True

        while True:
            # Bracha-style agreement
            sender, avss_msg = await recv()

            # IMPLICATE
            if avss_msg[0] == HbAVSSMessageType.IMPLICATE and not self.tagvars[tag]['in_share_recovery']:
                if sender not in implicate_set:
                    implicate_set.add(sender)
                    logger.debug("Handling Implicate Message [%d]", dealer_id)
                    # validate the implicate
                    #todo: implicate should be forwarded to others if we haven't sent one
                    if await self._handle_implication(tag, sender, avss_msg[1]):
                        # proceed to share recovery
                        logger.debug("Handle implication called [%d]", dealer_id)
                        self.tagvars[tag]['in_share_recovery'] = True
                        await self._handle_share_recovery(tag)
                        logger.debug("[%d] after implication", self.my_id)

            #todo find a more graceful way to handle different protocols having different recovery message types
            if avss_msg[0] in [HbAVSSMessageType.KDIBROADCAST, HbAVSSMessageType.RECOVERY1, HbAVSSMessageType.RECOVERY2]:
                await self._handle_share_recovery(tag, sender, avss_msg)
            # OK
            if avss_msg[0] == HbAVSSMessageType.OK and sender not in ok_set:
                # logger.debug("[%d] Received OK from [%d]", self.my_id, sender)
                ok_set.add(sender)

            # The only condition where we can terminate
            if (len(ok_set) == 3 * self.t + 1) and output:
                logger.debug("[%d] exit", self.my_id)
                break
    #@profile
    def _get_dealer_msg(self, values, n):
        # TODO(@sourav): Change this to handle 3 secrets
        # Probably we should make it generic in the number of secrets.
        #
        # Sample B random degree-(t) polynomials of form φ(·)
        # such that each φ_i(0) = si and φ_i(j) is Pj’s share of si
        # The same as B (batch_size)
        """
        while len(values) % (batch_size) != 0:
            values.append(0)
        """
        phi = [None]*self.sc
        phi_hat = [None]*self.sc
        commitments = [None]*self.sc
        # BatchPolyCommit
        #   Cs  <- BatchPolyCommit(SP,φ(·,k))
        # TODO: Whether we should keep track of that or not
        for k in range(self.sc):
            if k == 0:
                phi[k] = self.poly.random(self.t, values[k])
                commitments[k] = self.poly_commit.commit(phi[k], None)
            else:
                phi[k] = self.poly.random(self.t, values[k])
                phi_hat[k] = self.poly.random(self.t, ZR.rand())
                commitments[k] = self.poly_commit.commit(phi[k], phi_hat[k])


        ephemeral_secret_key = self.field.random()
        ephemeral_public_key = pow(self.g, ephemeral_secret_key)
        dispersal_msg_list = []
        for i in range(n):
            shared_key = pow(self.public_keys[i], ephemeral_secret_key)
            phis_i = [phi[k](i + 1) for k in range(self.sc)]
            phis_hat_i = [phi_hat[k](i + 1) for k in range(1, self.sc)]
            shares = dumps([phis_i, phis_hat_i])
            ciphertext = SymmetricCrypto.encrypt(str(shared_key).encode(), shares)
            dispersal_msg_list.append(ciphertext)

        # datab = serialize_gs(commitments[0]) # Serializing commitments
        # for k in range(1, secret_count):
        #     datab.extend(serialize_gs(commitments[k]))
        # datab.extend(serialize_g(ephemeral_public_key))

        datab = dumps((commitments, ephemeral_public_key, dispersal_msg_list))
        # datab.extend(dumps(dispersal_msg_list)) # Appending the AVID messages
        return bytes(datab)
    
    #@profile
    def _handle_dealer_msgs(self, tag, dispersal_msg, rbc_msg, dealer_id):
        # TODO(@sourav): Sample k secret, share one with Feldman and the remaining with Pedersen.
        commitments, ephemeral_public_key = rbc_msg
        shared_key = pow(ephemeral_public_key, self.private_key)
        self.tagvars[tag]['shared_key'] = shared_key
        self.tagvars[tag]['commitments'] = commitments
        self.tagvars[tag]['ephemeral_public_key'] = ephemeral_public_key
        
        try:
            sharesb = SymmetricCrypto.decrypt(str(shared_key).encode(), dispersal_msg)
        except ValueError as e:  # TODO: more specific exception
            logger.warn(f"Implicate due to failure in decrypting: {e}")
            return False
        
        if self.acss_status[dealer_id]: 
            self.tagvars[tag]['shares'] =  loads(sharesb)
            self.tagvars[tag]['witnesses'] = [None]
            return True
        return False

    #@profile
    async def avss(self, avss_id, values=None, dealer_id=None):
        """
        An acss with share recovery
        """
        # If `values` is passed then the node is a 'Sender'
        # `dealer_id` must be equal to `self.my_id`
        if values is not None:
            if dealer_id is None:
                dealer_id = self.my_id
            assert dealer_id == self.my_id, "Only dealer can share values."
        # If `values` is not passed then the node is a 'Recipient'
        # Verify that the `dealer_id` is not the same as `self.my_id`
        elif dealer_id is not None:
            assert dealer_id != self.my_id
        assert type(avss_id) is int

        # logger.debug(
        #     "[%d] Starting Batch AVSS. Id: %s, Dealer Id: %d",
        #     self.my_id,
        #     avss_id,
        #     dealer_id,
        # )

        n = self.n
        rbctag = f"{dealer_id}-{avss_id}-B-RBC"
        acsstag = f"{dealer_id}-{avss_id}-B-AVSS"

        self.tagvars[acsstag] = {}
        self.tagvars[acsstag]['tasks'] = []

        broadcast_msg = None
        if self.my_id == dealer_id:
            broadcast_msg = self._get_dealer_msg(values, n)

        send, recv = self.get_send(rbctag), self.subscribe_recv(rbctag)
        logger.debug("[%d] Starting reliable broadcast", self.my_id)

        async def predicate(_m):
            # TODO(@sourav): Fix this predicate message.
            dispersal_msg, commits, ephkey = self.decode_proposal(_m)
            return self.verify_proposal(dealer_id, dispersal_msg, commits, ephkey)

        
        
        output = asyncio.Queue()
        asyncio.create_task(
        optqrbc(
            rbctag,
            self.my_id,
            self.n,
            self.t,
            dealer_id,
            predicate,
            broadcast_msg,
            output.put_nowait,
            send,
            recv,
        ))
        rbc_msg = await output.get()

        # avss processing
        # logger.debug("starting acss")
        await self._process_avss_msg(avss_id, dealer_id, rbc_msg)
        
        for task in self.tagvars[acsstag]['tasks']:
            task.cancel()
        self.tagvars[acsstag] = {}
        del self.tagvars[acsstag]