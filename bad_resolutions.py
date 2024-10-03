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
	return cnt

def certificate_check(mism_resol):
	with open("mismatched_resolutions.csv", "r") as f_in, open("certificates.csv", "w") as f_out:
		r_in = csv.reader(f_in)
		csv.writer(f_out).writerow(["Domain", "Untrusted Certificate", "Mismatched Name", "Certificate Subject"])
		next(r_in)
		cnt = 0
		mism = 0
		invalid_mism = 0
		invalid = 0
		for row in r_in:
			expiration = 0
			try:
				result = subprocess.Popen("openssl s_client -showcerts -connect" + " " + row[0] + ":443", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
				stdout, stderr = result.communicate(input=b'Q\n', timeout=3)
			except subprocess.TimeoutExpired:
				result.kill()
				expiration = 1
			#print(stdout.decode())
			if expiration == 0:
				subject = stdout.decode().splitlines()[3].split("CN")[-1].lstrip("=")
				#print(subject)
				if stdout.decode().find("Verification: OK") != -1:
					if stdout.decode().find(row[0]) == -1:
						csv.writer(f_out).writerow([row[0], "N", "Y", subject])
						#print("ny")
						mism += 1
				else:
					if stdout.decode().find(row[0]) == -1:
						csv.writer(f_out).writerow([row[0], "Y", "Y", subject])
						#print("yy")
						invalid_mism += 1
					else:
						csv.writer(f_out).writerow([row[0], "Y", "N", subject])
						#print("yn")
						invalid += 1
			cnt += 1
			percentage(cnt / mism_resol * 100)
	print(f'\t{invalid + mism + invalid_mism} suspicious certificates found:\n\t{invalid} invalid certificates with matched name\n\t{mism} valid certificates with mismatched name\n\t{invalid_mism} invalid certificates with mismatched name')


def main():
	#print(f"\tCreating a list of untrusted resolutions (DNS resolvers: 210.2.4.8, 180.76.76.76)...")
	#domains = []
	#input(domains)
	#output(domains)
	#print(f"\tCompleted: 100.00%")
	#print(f"\tList of untrusted resolutions created -> ./output_bad.csv")
	#print(f"\tComparing good and bad resolutions...")
	#mismatched_resolutions = comparison()
	#print(f"\tList of mismatched resolutions created -> ./mismatched_resolutions.csv")
	certificate_check(49)

if __name__ == "__main__":
    	main()


