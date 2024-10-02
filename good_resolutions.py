import subprocess
import csv
import sys

def percentage(perc):
	print(f"\tCompleted: {perc:.2f}%", end="\r")

def input(dmns):

	with open("input.csv", "r") as f_in:
		csvreader = csv.reader(f_in)
		for row in csvreader:
			dmns.append(row[1])

def output(dmns):
	with open("output_good.csv", "w") as f_out:
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

def main():

	domains = []
	input(domains)
	output(domains)
	print(f"\tOperation completed!")

if __name__ == "__main__":
    	main()


