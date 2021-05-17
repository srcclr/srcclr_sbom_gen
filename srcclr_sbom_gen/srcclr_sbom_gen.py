#!/usr/bin/env python3

import sys, json

__version__ = "0.0.1"

def convert(results_file, output_file):
	
	if(results_file == "" or output_file == ""):
		print("Usage: srcclr-sbom-gen.py <scan_results.json> <output_file.json>")
		return


	sbom = {"bomFormat": "CycloneDX",'components':[]}
	components = []

	with open(results_file) as file:
		scanresults = json.load(file)
		records = scanresults['records']
		libraries = records[0]['libraries']
		for lib in libraries:
			coordinate2 = "" if lib['coordinate2'] == "" else ":" + lib['coordinate2']
			lib_name = lib['coordinate1'] if lib['coordinate2'] == "" else lib['coordinate1'] + "/" + lib['coordinate2']
			try:
				hash_sha1 = lib['versions'][0]['sha1']
			except:
				hash_sha1 = ""
			try:
				hash_sha2 = lib['versions'][0]['sha2']
			except:
				hash_sha2 = ""
			purl = "pkg:{}/{}@{}".format(lib['coordinateType'].lower(), lib_name, lib["versions"][0]['version'])
			for c in components:
				if c['purl'] == purl:
					continue
			dataset = {
			"description": lib['description'],
			"hashes": [
				{
					"alg": "SHA-1",
					"content": hash_sha1
				},
				{
					"alg": "SHA-256",
					"content": hash_sha2
				}],
			"licenses": lib['versions'][0]['licenses'],
			"modified": False,
			"name": "{}{}".format(lib['coordinate1'], coordinate2),
			"publisher": lib['author'],
			"purl": purl,
			"type": "library",
			"version": lib["versions"][0]['version']
			}
			components.append(dataset)


	with open(output_file, 'w') as outfile:
		sbom['components'] = components
		json.dump(sbom, outfile, indent=4, sort_keys=True)


#Run as script
if __name__ == "__main__":
	if(len(sys.argv) != 3):
			print("Usage: srcclr-sbom-gen.py <scan_results.json> <output_file.json>")
			sys.exit()

	convert(sys.argv[1], sys.argv[2])

