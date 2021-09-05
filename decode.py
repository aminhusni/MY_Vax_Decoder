import zlib
import cwt
import base45
import datetime
import argparse
import cbor2

HEADER_MAGIC = 'HC1:'

parser = argparse.ArgumentParser("Malaysian Vax QR Decoder")
parser.add_argument("--qrtext", help="The decoded QR in text form (qr.txt)")
parser.add_argument("--verbose", default="", help="Verbose mode (y/n)")
args = parser.parse_args()

# Public key have to obtain from somewhere...

with open(args.qrtext) as f:
    qr_data = f.read()

qr_data = qr_data.rstrip()
if not qr_data.startswith(HEADER_MAGIC):
    raise Exception("Not a vaccine QR")

qr_data = qr_data[len(HEADER_MAGIC):]
qr_data = base45.b45decode(qr_data)

decompressed = zlib.decompress(qr_data)

#Get the KID value
raw = cbor2.loads(decompressed)
signature_kid = raw.value[0][5:]

with open("pubkey.pem") as f:
    pem = f.read()
    public_key = cwt.COSEKey.from_pem(pem, kid=signature_kid)

try:
    cwt_data = cwt.decode(decompressed, public_key)

except:
    print(" --- ERROR! --- Signature is INVALID!")
    exit()

print("++ Certificate signature valid :) ++")
print("")

if args.verbose == "y":
    print(cwt_data)

country = cwt_data[1]
batch = cwt_data[-260][1]['v'][0]['bn']
date_jab = cwt_data[-260][1]['v'][0]['dt']
loc_jab = cwt_data[-260][1]['v'][0]['is']
manufacturer = cwt_data[-260][1]['v'][0]['ma']
vax_type = cwt_data[-260][1]['v'][0]['mp']
vax_type2 = cwt_data[-260][1]['v'][0]['vp']
name_rep = cwt_data[-260][1]['nam']['fn']

print("Country:", country)
print("Administered by:", loc_jab)
print("Injection date:", date_jab)
print("Vaccine brand:", vax_type)
print("Vaccine type", vax_type2)
print("Manufacturer:", manufacturer)
print("Vaccine Batch:", batch)
print("Recepient name:", name_rep)


issue_ts = cwt_data[6]
expire_ts = cwt_data[4]
print("")
print("Times are local time.")
print("Certificate issued at:", datetime.datetime.fromtimestamp(issue_ts))
print("Certificate expires at:", datetime.datetime.fromtimestamp(expire_ts))