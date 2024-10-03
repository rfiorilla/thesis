import time
import signal
import subprocess
import csv
import sys

def percentage(perc):
	print(f"\tCompleted: {perc:.2f}%", end="\r")

def input(dmns):
	with open("input.csv", "r") as f_in:
		r_in = csv.reader(f_in)
		for row in r_in:
			dmns.append(row[1])

def output(dmns):
	with open("output_bad.csv", "w") as f_out:
		csv.writer(f_out).writerow(['Domain', 'IP Address'])
		cnt = 0
		for d in dmns:
			result = subprocess.run("nslookup" + " " + d, shell=True, capture_output=True, text=True)
			if result.stdout.find("No answer") == -1:
				ip = result.stdout.splitlines()[5].split()[-1]
			else:
				ip = "N/A"
			csv.writer(f_out).writerow([d, ip])
			cnt += 1
			percentage(cnt / len(dmns) * 100)

def comparison():
	with open("output_good.csv", "r") as f_good, open("output_bad.csv", "r") as f_bad, open("mismatched_resolutions.csv", "w") as f_mism:
		r_good = csv.reader(f_good)
		r_bad = csv.reader(f_bad)
		csv.writer(f_mism).writerow(['Domain', 'Good IP Address', 'Bad IP Address'])
		next(r_good)
		next(r_bad)
		cnt = 0
		for row1, row2 in zip(r_good, r_bad):
			if row1 != row2 and row1[1].find("N/A") == -1 and row2[1].find("N/A") == -1:
				csv.writer(f_mism).writerow([row1[0], row1[1], row2[1]])
				cnt += 1
		print(f"\t{cnt} mismatched resolutions found.")

def certificate_check():
	with open("provina.csv", "r") as f_in, open("certificates.csv", "w") as f_out:
		r_in = csv.reader(f_in)
		csv.writer(f_out).writerow(["Domain", "Untrusted Certificate", "Mismatched Name"])
		next(r_in)
		for row in r_in:
			result = subprocess.Popen("openssl s_client -showcerts -connect google.com:443", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
			stdout, stderr = result.communicate(input=b'Q\n')
			print(stdout.decode())
			if stdout.decode().find("Verification: OK") != -1:
				if stdout.decode().find(row[0]) == -1:
					csv.writer(f_out).writerow([row[0], "N", "Y"])
					print("ny")
			else:
				if stdout.decode().find(row[0]) == -1:
					csv.writer(f_out).writerow([row[0], "Y", "Y"])
					print("yy")
				else:
					csv.writer(f_out).writerow([row[0], "Y", "N"])
					print("yn")


def main():
	#print(f"\tCreating a list of untrusted resolutions (DNS resolvers: 210.2.4.8, 180.76.76.76)...")
	#domains = []
	#input(domains)
	#output(domains)
	#print(f"\tCompleted: 100.00%")
	#print(f"\tList of untrusted resolutions created -> ./output_bad.csv")
	#print(f"\tComparing good and bad resolutions...")
	#comparison()
	#print(f"\tList of mismatched resolutions created -> ./mismatched_resolutions.csv")
	certificate_check()

if __name__ == "__main__":
    	main()


