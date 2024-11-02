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

def test_resolutions(dmns):
	with open("output_test.csv", "w") as f_out:
		csv.writer(f_out).writerow(["Domain", "IP Address"])
		cnt = 0
		for d in dmns:
			result = subprocess.run("nslookup" + " " + d, shell=True, capture_output=True, text=True)
			if result.stdout.find("No answer") == -1:
				try:
					ip = result.stdout.splitlines()[5].split()[-1]
				except IndexError:
					ip = "N/A"
			else:
				ip = "N/A"
			csv.writer(f_out).writerow([d, ip])
			cnt += 1
			percentage(cnt / len(dmns) * 100)
		print(f"\tCompleted: 100.00%")

def comparison():
	with open("output_control.csv", "r") as f_good, open("output_test.csv", "r") as f_bad, open("mismatched_resolutions.csv", "w") as f_mism:
		r_good = csv.reader(f_good)
		r_bad = csv.reader(f_bad)
		csv.writer(f_mism).writerow(["Domain", "Control IP Address", "Test IP Address"])
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
		csv.writer(f_out).writerow(["Domain", "Untrusted Certification Chain", "Mismatched Name", "Certificate Subject"])
		next(r_in)
		cnt = 0
		mism = 0
		invalid_mism = 0
		invalid = 0
		subprocess.run("rm -rf certificates/*", shell=True, capture_output=True, text=True)
		for row in r_in:
			suspicious = 0
			flag = 0
			expiration = 0
			try:
				result = subprocess.Popen("openssl s_client -showcerts -connect" + " " + row[0] + ":443 -CAfile ./mozilla_trusted_ca_list.crt", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
				stdout, stderr = result.communicate(input=b'Q\n', timeout=4)
			except subprocess.TimeoutExpired:
				result.kill()
				expiration = 1
			if expiration == 0:
				san = subprocess.run("echo" + " \"" + stdout.decode() + "\" | " + "openssl x509 -noout -text", shell=True, capture_output=True, text=True)
				try:
					subject = stdout.decode().splitlines()[3].split("CN")[-1].lstrip("=")
				except IndexError:
					flag = 1
				if flag == 0:
					if stdout.decode().find("Verification: OK") != -1:
						if san.stdout.find(row[0]) == -1 and san.stdout.find('.'.join(row[0].split('.')[-2:])) == -1 and subject.find(row[0]) == -1 and subject.find('.'.join(row[0].split('.')[-2:])) == -1:
							csv.writer(f_out).writerow([row[0], "N", "Y", subject])
							mism += 1
							suspicious = 1
					else:
						if san.stdout.find(row[0]) == -1 and san.stdout.find('.'.join(row[0].split('.')[-2:])) == -1 and subject.find(row[0]) == -1 and subject.find('.'.join(row[0].split('.')[-2:])) == -1:
							csv.writer(f_out).writerow([row[0], "Y", "Y", subject])
							invalid_mism += 1
							suspicious = 1
						else:
							csv.writer(f_out).writerow([row[0], "Y", "N", subject])
							invalid += 1
							suspicious = 1
					if suspicious == 1:
						with open ("certificates/" + row[0].replace('.', '_') + ".txt", "w") as cert:
							cert.write("---------- ORIGINAL FORMAT ----------\n" + stdout.decode() + "\n" + "---------- READABLE FORMAT ----------\n" + san.stdout)
			cnt += 1
			percentage(cnt / mism_resol * 100)
	print(f"\tCompleted: 100.00%")
	print(f'\t{invalid + mism + invalid_mism} suspicious certificates found:\n\t{invalid} invalid certificates with matched name\n\t{mism} valid certificates with mismatched name\n\t{invalid_mism} invalid certificates with mismatched name')
	return invalid + mism + invalid_mism

def blockpage_score_calculator(page):
	with open("blockpage_typical_words.csv", "r") as f_in:
		r_in = csv.reader(f_in)
		next(r_in)
		tmp_score = 0
		for row in r_in:
			if page.lower().find(row[1]) != -1:
				tmp_score += (int(row[0]) * int(row[0]))
		if len(page) > 0:
			score = tmp_score / (len(page) * len(page)) * 1000
		else:
			score = 0
	return score

def csv_sorter(csv_file):
	with open(csv_file, "r") as f_in:
		r_in = csv.reader(f_in)
		header = next(r_in)
		sorted_rows = sorted(r_in, key=lambda row: float(row[2]), reverse=True)
	with open(csv_file, "w") as f_out:
		csv.writer(f_out).writerow(header)
		i = 0
		for row in sorted_rows:
			csv.writer(f_out).writerow([sorted_rows[i][0], sorted_rows[i][1], sorted_rows[i][2]])
			i += 1

def curler(certs):
	with open("certificates.csv", "r") as f_in, open("webpages.csv", "w") as f_out:
		r_in = csv.reader(f_in)
		next(r_in)
		csv.writer(f_out).writerow(["Domain", "HTTP Status Code", "Blockpage Score"])
		cnt = 0
		curled = 0
		subprocess.run("rm -rf webpages/*", shell=True, capture_output=True, text=True)
		for row in r_in:
			expiration = 0
			try:
				result = subprocess.Popen("curl https://" + row[0]  + " " + "-i -k -L", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
				stdout, stderr = result.communicate(timeout=2)
			except subprocess.TimeoutExpired:
				result.kill()
				expiration = 1
			if (expiration != 1):
				try:
					score = blockpage_score_calculator(stdout.decode(encoding='latin-1').split("\n\r\n")[-1])
					status = stdout.decode(encoding='latin-1').split("\n\r\n")[-2].splitlines()[0].split()[1]
					csv.writer(f_out).writerow([row[0], status, round(score, 2)])
					with open ("webpages/" + row[0].replace('.', '_') + ".html", "w") as html:
						html.write(stdout.decode(encoding='latin-1').split("\n\r\n")[-1])
					curled += 1
				except IndexError:
					pass
			cnt += 1
			percentage(cnt / certs * 100)
	print(f"\tCompleted: 100.00%")
	csv_sorter("webpages.csv")
	print(f"\t{curled} pages retrieved.")

def main():
	print(f"\tCreating a list of untrusted resolutions...")
	domains = []
	input(domains)
	test_resolutions(domains)
	print(f"\tList of untrusted resolutions created -> ./output_bad.csv")
	print(f"\tComparing good and bad resolutions...")
	mismatched_resolutions = comparison()
	print(f"\tList of mismatched resolutions created -> ./mismatched_resolutions.csv")
	print(f"\tAnalyzing the certificates of websites with mismatched resolutions...")
	suspicious_certificates = certificate_check(mismatched_resolutions)
	print(f"\tList of suspicious certificates created -> ./certificates.csv")
	print(f"\tObtaining web pages of suspicious websites...")
	curler(suspicious_certificates)
	print(f"\tList of possible censored websites generated -> ./webpages.csv")
	print(f"\tWebpages' HTMLs collected -> ./webpages/")

if __name__ == "__main__":
    	main()

