from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.ABEnc import ABEnc
from msp import MSP

debug = False


class CP_ABE(ABEnc):
    def __init__(self, group_obj, assump_size, verbose=False):
        ABEnc.__init__(self)
        self.group = group_obj
        self.assump_size = assump_size  # size of linear assumption, at least 2
        self.util = MSP(self.group, verbose)

    def keygen(self, public_key, master_secrete_key, attribute_lst):
        """
        Generate a key for a list of attributes.
        """

        if debug:
            print('\nKey generation algorithm:\n')

        # pick randomness
        r = []
        sum = 0
        for i in range(self.assump_size):
            rand = self.group.random(ZR)
            r.append(rand)
            sum += rand

        # compute the [Br]_2 term

        # first compute just Br as it will be used later too
        Br = []
        for i in range(self.assump_size):
            Br.append(master_secrete_key['B'][i] * r[i])
        Br.append(sum)

        # now compute [Br]_2
        K_0 = []
        for i in range(self.assump_size + 1):
            K_0.append(master_secrete_key['h'] ** Br[i])

        # compute [W_1 Br]_1, ...
        K = {}
        A = master_secrete_key['A']
        g = master_secrete_key['g']
        for attr in attribute_lst:
            key = []
            sigma_attr = self.group.random(ZR)
            for t in range(self.assump_size):
                prod = 1
                a_t = A[t]
                for l in range(self.assump_size + 1):
                    input_for_hash = attr + str(l) + str(t)
                    prod *= (self.group.hash(input_for_hash, G1) ** (Br[l]/a_t))
                prod *= (g ** (sigma_attr/a_t))
                key.append(prod)
            key.append(g ** (-sigma_attr))
            K[attr] = key

        # compute [k + VBr]_1
        Kp = []
        g_k = master_secrete_key['g_k']
        sigma = self.group.random(ZR)
        for t in range(self.assump_size):
            prod = g_k[t]
            a_t = A[t]
            for l in range(self.assump_size + 1):
                input_for_hash = '01' + str(l) + str(t)
                prod *= (self.group.hash(input_for_hash, G1) ** (Br[l] / a_t))
            prod *= (g ** (sigma / a_t))
            Kp.append(prod)
        Kp.append(g_k[self.assump_size] * (g ** (-sigma)))

        return {'attribute_lst': attribute_lst, 'K_0': K_0, 'K': K, 'Kp': Kp}

    def decrypt(self, public_key, cipher_text, key):
        """
        Decrypt ciphertext cipher_text with key key.
        """

        if debug:
            print('\nDecryption algorithm:\n')

        nodes = self.util.prune(cipher_text['policy'], key['attribute_lst'])
        if not nodes:
            print ("Policy not satisfied.")
            return None

        product_GT1 = 1
        prod2_GT = 1
        for i in range(self.assump_size + 1):
            product_H = 1
            product_G = 1
            for node in nodes:
                attr = node.getAttributeAndIndex()
                attr_stripped = self.util.strip_index(attr)
                product_H *= key['K'][attr_stripped][i]
                product_G *= cipher_text['C'][attr][i]
            product_GT1 *= pair(key['Kp'][i] * product_H, cipher_text['C_0'][i])
            prod2_GT *= pair(product_G, key['K_0'][i])

        return cipher_text['Cp'] * prod2_GT / product_GT1

    def encrypt(self, public_key, msg, policy_str):
        """
        Encrypt a message msg under a policy string.
        """

        if debug:
            print('\nEncryption algorithm:\n')

        policy = self.util.createPolicy(policy_str)
        mono_span_prog = self.util.convert_policy_to_msp(policy)
        num_cols = self.util.len_longest_row

        # pick randomness
        s = []
        sum = 0
        for i in range(self.assump_size):
            rand = self.group.random(ZR)
            s.append(rand)
            sum += rand

        # compute the [As]_2 term
        C_0 = []
        h_A = public_key['h_A']
        for i in range(self.assump_size):
            C_0.append(h_A[i] ** s[i])
        C_0.append(h_A[self.assump_size] ** sum)

        # compute the [(V^T As||U^T_2 As||...) M^T_i + W^T_i As]_1 terms

        # pre-compute hashes
        hash_table = []
        for j in range(num_cols):
            x = []
            input_for_hash1 = '0' + str(j + 1)
            for l in range(self.assump_size + 1):
                y = []
                input_for_hash2 = input_for_hash1 + str(l)
                for t in range(self.assump_size):
                    input_for_hash3 = input_for_hash2 + str(t)
                    hashed_value = self.group.hash(input_for_hash3, G1)
                    y.append(hashed_value)
                x.append(y)
            hash_table.append(x)

        C = {}
        for attr, row in mono_span_prog.items():
            ct = []
            attr_stripped = self.util.strip_index(attr)
            for l in range(self.assump_size + 1):
                prod = 1
                cols = len(row)
                for t in range(self.assump_size):
                    input_for_hash = attr_stripped + str(l) + str(t)
                    prod1 = self.group.hash(input_for_hash, G1)
                    for j in range(cols):
                        prod1 *= (hash_table[j][l][t] ** row[j])
                    prod *= (prod1 ** s[t])
                ct.append(prod)
            C[attr] = ct

        # compute the e(g, h)^(k^T As) . m term
        Cp = 1
        for i in range(self.assump_size):
            Cp = Cp * (public_key['e_gh_kA'][i] ** s[i])
        Cp = Cp * msg

        return {'policy': policy, 'C_0': C_0, 'C': C, 'Cp': Cp}


    def setup(self):
        """
        Generates public key and master secret key.
        """

        if debug:
            print('\nSetup algorithm:\n')

        # generate two instances of the k-linear assumption
        A = []
        B = []
        for i in range(self.assump_size):
            A.append(self.group.random(ZR))
            B.append(self.group.random(ZR))  # note that A, B are vectors here

        # vector
        k = []
        for i in range(self.assump_size + 1):
            k.append(self.group.random(ZR))

        # pick a random element from the two source groups and pair them
        g = self.group.random(G1)
        h = self.group.random(G2)
        e_gh = pair(g, h)

        # now compute various parts of the public parameters

        # compute the [A]_2 term
        h_A = []
        for i in range(self.assump_size):
            h_A.append(h ** A[i])
        h_A.append(h)

        # compute the e([k]_1, [A]_2) term
        g_k = []
        for i in range(self.assump_size + 1):
            g_k.append(g ** k[i])

        e_gh_kA = []
        for i in range(self.assump_size):
            e_gh_kA.append(e_gh ** (k[i] * A[i] + k[self.assump_size]))

        # the public key
        public_key = {'h_A': h_A, 'e_gh_kA': e_gh_kA}

        # the master secret key
        master_secrete_key = {'g': g, 'h': h, 'g_k': g_k, 'A': A, 'B': B}

        return public_key, master_secrete_key


