import subprocess
import csv

def main():

	domains = []

	with open("input.csv", "r") as f_in:
		csvreader = csv.reader(f_in)
		for row in csvreader:
			domains.append(row[1])

	with open("output_good.csv", "w") as f_out:
		csv.writer(f_out).writerow(['Domain', 'IP Address'])
		for d in domains:
			result = subprocess.run("nslookup" + " " + d, shell=True, capture_output=True, text=True)
			if result.stdout.find("No answer") == -1:
				ip = result.stdout.splitlines()[5].split()[-1]
			else:
				ip = "N/A"
			csv.writer(f_out).writerow([d, ip])

if __name__ == "__main__":
    	main()


