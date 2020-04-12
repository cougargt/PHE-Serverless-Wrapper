import json
import math
import requests
import phe.encoding
from phe import paillier

# hardcoded public and private keys for testing
#public:
n = 3738502394862799900759022619738152580416694540566289796758507351453649927207797608800376899894213195447839757729922780798199975999307643586799474170653337618302804199611433400571799826946057269100575785949958760631859073477277222748692676718447241077943656941804307589239276104863829741452561619956154374511467977153068702033380606090860566537253458103244069269794039780864522887104654451107349631433145013063477332564294383149602831796084133262263502680017347006558169674168229848091442796533875515715081853890537606187295614332894578999677544593825741622458237498153527048087992565621138680127514711440359838425235243006549143718987972664084512505843036629434053606791535673275359142102703498876324194279288162461427250478162823110382159175477378887423409853748705281554066143906358527267314775637589088438594520253019680163995116183384003946336651246150796702016874892746720147532469453634195956543348969995978904123119559
#private
p = 1865880119796016900780895887655704785360326310009725171971293298493180445895278683079991690705432185323799353648305986579087276408664340500266870614080588351396985712503626085842089167243860263645093687484754307352757692665805213204447049293176404396868872401480683562232785875065333959751177717386418664175572850090627114110276838640409062433767575694245871667481566036484036903938700473341228738675011473214214460283791644976189958577128300746214715561351697209
q = 2003613391449555274742839824279113483327781354393747165846702040156443639705692162032920650252976131612497421807812673020963316100612233882536011757438826631917284073219075773910725143876677438160028321289306533884301002064692687772806703535057444227039239176331979657667649806661834701107198816659726262416915611263754589975636735764162961842073438205501821399761141794752011976898073109357942060476074272103628819104140092627222581829932942391867263661330449151

public_key = phe.paillier.PaillierPublicKey(n=n)
private_key = phe.paillier.PaillierPrivateKey(public_key=public_key, p=p, q=q)

# define endpoints
url_hello =  "https://hx4m0vecik.execute-api.us-east-1.amazonaws.com/dev/hello"
url_enc =    "https://hx4m0vecik.execute-api.us-east-1.amazonaws.com/dev/encrypt"
url_dec =    "https://hx4m0vecik.execute-api.us-east-1.amazonaws.com/dev/decrypt"
url_add_ee = "https://hx4m0vecik.execute-api.us-east-1.amazonaws.com/dev/add_ee"
url_add_ep = "https://hx4m0vecik.execute-api.us-east-1.amazonaws.com/dev/add_ep"
url_mul_ep = "https://hx4m0vecik.execute-api.us-east-1.amazonaws.com/dev/mul_ep"

# test all the API endpoints

def jsonFromEncr(value):
    out = value.__dict__.copy()
    out_pubk = out.pop('public_key')
    out['public_key'] = out_pubk.__dict__
    return out

def encrFromJson(json):
    pubK = paillier.PaillierPublicKey(n=json['public_key']['n'])
    value = paillier.EncryptedNumber(public_key=pubK, ciphertext=json['_EncryptedNumber__ciphertext'], exponent=json['exponent'])
    value._EncryptedNumber__is_obfuscated = json['_EncryptedNumber__is_obfuscated']
    return value

def sendRequest(body, url, expected):
    resp = requests.post(url, json=body)
    print(resp)
    c_enc = encrFromJson(json.loads(resp.text))
    c = private_key.decrypt(c_enc)
    print("Got:" +str(c) + " Expected:" + str(expected))


a = 1234
b = 4567
a_enc = public_key.encrypt(a)
b_enc = public_key.encrypt(b)

# test Hello - used for timing estimation
print("===hello===")
resp = requests.post(url_hello)
print(resp)

# test Add Encrypted+Encrypted
print("===add e+e===")
body = {'a_encr': jsonFromEncr(a_enc), 'b_encr': jsonFromEncr(b_enc)}
sendRequest(body, url_add_ee, a+b)

# test Add Encrypted + plaintext
print("===add E+P===")
body = {'a_encr': jsonFromEncr(a_enc), 'b_pt': b}
sendRequest(body, url_add_ep, a+b)

# test mult Encrypted + plaintext
print("===Mult===")
body = {'a_encr': jsonFromEncr(a_enc), 'b_pt': b}
sendRequest(body, url_mul_ep, a*b)

# test encrypt
print("===encrypt===")
body = {'public_key': n, 'b_pt': b}
sendRequest(body, url_enc, b)

# test decrypt
print("===Decrypt===")
body = {'n': n, 'p': p, 'q': q, 'a_encr': jsonFromEncr(a_enc)}
#sendRequest(body, url_dec, a)
resp = requests.post(url_dec, json=body)
print(body)
c = json.loads(resp.text)['c_pt']
print("Got:" + str(c) + " Expected:" + str(a))
