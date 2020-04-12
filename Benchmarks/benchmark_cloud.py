"""
Benchmark key generation, encryption and decryption.

"""
import requests

import random
import time
import phe.paillier as paillier

url_hello = "https://hx4m0vecik.execute-api.us-east-1.amazonaws.com/dev/hello"
url_enc = "https://hx4m0vecik.execute-api.us-east-1.amazonaws.com/dev/encrypt"
url_dec = "https://hx4m0vecik.execute-api.us-east-1.amazonaws.com/dev/decrypt"
url_add_ee = "https://hx4m0vecik.execute-api.us-east-1.amazonaws.com/dev/add_ee"
url_add_ep = "https://hx4m0vecik.execute-api.us-east-1.amazonaws.com/dev/add_ep"
url_mul_ep = "https://hx4m0vecik.execute-api.us-east-1.amazonaws.com/dev/mul_ep"


def jsonFromEncr(value):
    out = value.__dict__.copy()
    out_pubk = out.pop('public_key')
    out['public_key'] = out_pubk.__dict__
    return out


def sendRequest(body, url):
    resp = requests.post(url, json=body)
    assert(resp.status_code == 200)


def bench_encrypt(pubkey, nums):
    for num in nums:
        body = {'public_key': pubkey.n, 'b_pt': num}
        sendRequest(body, url_enc)


def bench_decrypt(prikey, nums):
    for num in nums:
        body = {'n': prikey.public_key.n, 'p': prikey.p, 'q': prikey.q, 'a_encr': jsonFromEncr(num)}
        # sendRequest(body, url_dec, a)
        resp = requests.post(url_dec, json=body)


def bench_add_ee(nums1, nums2):
    for num1, num2 in zip(nums1, nums2):
        body = {'a_encr': jsonFromEncr(num1), 'b_encr': jsonFromEncr(num2)}
        sendRequest(body, url_add_ee)


def bench_add_ep(nums1, nums2):
    for num1, num2 in zip(nums1, nums2):
        body = {'a_encr': jsonFromEncr(num1), 'b_pt': num2}
        sendRequest(body, url_add_ep)


def bench_mul(nums1, nums2):
    for num1, num2 in zip(nums1, nums2):
        body = {'a_encr': jsonFromEncr(num1), 'b_pt': num2}
        sendRequest(body, url_mul_ep)

def ping(test_size):
    for x in range(0, test_size):
        resp = requests.post(url_hello)
        assert(resp.status_code == 200)


def time_method(method, *args):
    start = time.time()
    method(*args)
    return time.time() - start


def bench_time(test_size, key_size=128):

    print('Paillier Benchmarks with key size of {} bits'.format(key_size))
    pubkey, prikey = paillier.generate_paillier_keypair(n_length=key_size)
    nums1 = [random.random() for _ in range(test_size)]
    nums2 = [random.random() for _ in range(test_size)]
    nums1_enc = [pubkey.encrypt(n) for n in nums1]
    nums2_enc = [pubkey.encrypt(n) for n in nums2]
    ones = [1.0 for _ in range(test_size)]


    times_raw = [
        time_method(bench_encrypt, pubkey, nums1),
        time_method(bench_decrypt, prikey, nums1_enc),
        time_method(bench_add_ep, nums1_enc, nums2),
        time_method(bench_add_ee, nums1_enc, nums2_enc),
        time_method(bench_add_ep, nums1_enc, ones),
        time_method(bench_mul, nums1_enc, nums2)
    ]
    times = [t / test_size for t in times_raw]
    latency = time_method(ping, test_size)
    times_adj = [(t - latency) / test_size for t in times_raw]
    ops = [int(1.0 / t) for t in times]
    ops_adj = [int(1.0 / t) for t in times_adj]
    '''
    print(
        '=====Raw Timing including Latency to/from server===='
        'operation: time in seconds (# operations per second)\n'
        'encrypt: {:.6f} s ({} ops/s)\n'
        'decrypt: {:.6f} s ({} ops/s)\n'
        'add unencrypted and encrypted: {:.6f} s ({} ops/s)\n'
        'add encrypted and encrypted: {:.6f} s ({} ops/s)\n'
        'add encrypted and 1: {:.6f} s ({} ops/s)\n'
        'multiply encrypted and unencrypted: {:.6f}  s ({} ops/s)'.format(
            times[0], ops[0], times[1], ops[1], times[2], ops[2],
            times[3], ops[3], times[4], ops[4], times[5], ops[5]
        )
    )
    '''
    print('{:.6f}\t{:.6f}\t{:.6f}\t{:.6f}\t{:.6f}\t{:.6f}'.format(times[0], times[1], times[2], times[3], times[4], times[5]))
    '''
    print(
        '====Adjusted Timing including Latency to/from server===='
        'operation: time in seconds (# operations per second)\n'
        'encrypt: {:.6f} s ({} ops/s)\n'
        'decrypt: {:.6f} s ({} ops/s)\n'
        'add unencrypted and encrypted: {:.6f} s ({} ops/s)\n'
        'add encrypted and encrypted: {:.6f} s ({} ops/s)\n'
        'add encrypted and 1: {:.6f} s ({} ops/s)\n'
        'multiply encrypted and unencrypted: {:.6f}  s ({} ops/s)'.format(
            times_adj[0], ops_adj[0], times_adj[1], ops_adj[1], times_adj[2], ops_adj[2],
            times_adj[3], ops_adj[3], times_adj[4], ops_adj[4], times_adj[5], ops_adj[5]
        )
    )
    '''
    return times

'''
def bench_mem(test_size):
    r_init = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    pubkey, prikey = paillier.generate_paillier_keypair()
    nums = []
    for i in range(test_size):
        if not i % 10000:
            # This is probably KB (i.e. 1000 bytes) when run on linux
            r = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss - r_init
            print('Memory usage for {:,} encrypted numbers = {:,} ({:.4f} per '
                  'number)'.format(i, r, i and r / i))
        nums.append(pubkey.encrypt(random.random()))

# bench_mem(1000000)  # NOTE: this will take a long time
'''

times = []
#key_sizes = [128, 256, 512, 1024, 2048, 4096, 8192]
key_sizes = [128, 256, 512, 1024, 2048, 4096]
for key_size in key_sizes:
    times.append(bench_time(30, key_size))
