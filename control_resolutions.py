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
	with open("output_control.csv", "w") as f_out:
		csv.writer(f_out).writerow(['Domain', 'IP Address'])
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

def main():
	print(f"\tCreating a list of trusted resolutions...")
	domains = []
	input(domains)
	output(domains)
	print(f"\tCompleted: 100.00%")
	print(f"\tList of trusted resolutions created -> ./output_control.csv")

if __name__ == "__main__":
    	main()


