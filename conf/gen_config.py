import sys 
import os

n = int(sys.argv[1])
t = int(sys.argv[2])
k = int(sys.argv[3])

header = "{\n"
header += f"\t\"N\":{n},\n"
header += f"\t\"t\":{t},\n"
header += f"\t\"k\":{k},\n"

peers = "\t\"peers\": [\n"
for i in range(n-1):
    peers += f"\t\t\"0.0.0.0:{13000+i}\",\n"
peers += f"\t\t\"0.0.0.0:{13000+n-1}\"\n"

footer = "\t]\n}"

path = f"adkg_{n}"
if not os.path.exists(path):
    os.makedirs(path)

for i in range(n):
    file_name = path+f"/local.{i}.json"
    ofile  = open(file_name, "w")
    config = header + f"\t\"my_id\": {i},\n" + peers + footer
    ofile.write(config)