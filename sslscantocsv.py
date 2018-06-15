#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from collections import namedtuple, OrderedDict
import xml.etree.ElementTree as ET
from sys import argv, stdout
import csv



if len(argv)!=2:
	print "Usage : %s <filename>"%argv[0]
	exit(1)

column_labels=OrderedDict()
column_labels['sslversion']="Protocole"
column_labels['cipheralgo']="Algorithme de chiffrement"
column_labels['cipherbits']="Taille de la clé (bits)"
column_labels['mode']="Mode"
column_labels['kexalgo']="Algorithme d'échange de clés"
#column_labels['dhbits']="Taille du groupe d'echange de cle"
column_labels['hashmacalgo']="Fonction de hachage"
Cipher=namedtuple("Cipher", column_labels.iterkeys())

def parse_file_for_ciphers(name):
	tree=ET.parse(name)
	ciphers=[]
	ciphers_raw=tree.iter("cipher")
	for c in ciphers_raw:
		sslversion=c.get("sslversion")
		cipherbits=c.get("bits")
		cipher_info=c.get("cipher")
		#Default key-exchange algorithm if none mentionned
		kexalgo="RSA"
		#dhbits="N/A"
		#Default mode if block cipher and none mentionned
		mode="CBC"
		cipheralgo="UNIDENTIFIED"
		hashmacalgo="UNIDENTIFIED"
		for inf in cipher_info.split("-"):
			#Key-exchange algorithms
			if inf in ["DHE", "EDH"]:
				kexalgo="DHE (%d bits)"% int(c.get("dhebits"))
			elif inf in ["DH"]:
				kexalgo="DH (%d bits)"% int(c.get("dhbits"))
			elif inf in ["ECDHE"]:
				kexalgo="ECDHE (%d bits)" % int(c.get("ecdhebits"))
			elif inf in ["ECDH"]:
				kexalgo="ECDH (%d bits)" % int(c.get("ecdhbits"))
			elif inf in ["AECDH"]:
				kexalgo="AECDH (%d bits)" % int(c.get("ecdhebits"))
				#dhbits=c.get("ecdhebits")
			elif inf in ["RSA"]:
				pass
			
			#ciphers
			elif inf in ["AES", "AES128", "AES256"]:
				cipheralgo="AES"
			elif inf in ["CAMELLIA", "CAMELLIA128", "CAMELLIA256"]:
				cipheralgo="CAMELLIA"
			elif inf in ["DES", "3DES"]:
				if cipherbits==56:
					cipheralgo="DES"
				else:
					cipheralgo="3DES"
			elif inf in ["SEED", "IDEA", "RC4", "RC2", "NULL"]:
				cipheralgo=inf

			#hash-MAC algorithms
			elif inf in ["MD5"]:
				hashmacalgo="MD5"
			elif inf in ["SHA"]:
				hashmacalgo="SHA-1"
			elif inf in ["SHA256", "SHA384"]:
				hashmacalgo="SHA-2"
				
			#cipher modes
			elif inf in ["GCM"]:
				mode="GCM"
			elif inf in ["CBC", "CBC3"]:
				pass
			
			#other (to ignore)
			elif inf in ["EXP"]:
				pass

			#defaut
			else:
				print "Unidentified tag :",inf
				print "Please complete the script to match this tag"
		ciphers.append(Cipher(sslversion=sslversion, kexalgo=kexalgo, cipheralgo=cipheralgo, mode=mode, cipherbits=cipherbits, hashmacalgo=hashmacalgo))#dhbits=dhbits
	return ciphers

def compare_ciphers(ca,cb):
	#compare SSL/TLS versions
	sslversions=["SSLv2", "SSLv3", "TLSv1.0" , "TLSv1.1", "TLSv1.2"]
	res=sslversions.index(ca.sslversion)-sslversions.index(cb.sslversion)
	if res!=0:
		return res

	#if equals, compare cipher algos
	cipheralgos=["NULL", "DES", "RC2", "RC4", "3DES" , "IDEA", "SEED", "CAMELLIA", "AES"]
	res=cipheralgos.index(ca.cipheralgo)-cipheralgos.index(cb.cipheralgo)
	if res!=0:
		return res
	
	#if equals, compare cipher bits strength
	res=int(ca.cipherbits)-int(cb.cipherbits)
	if res!=0:
		return res
	
	#if equals, compare key-exchange algorithms
	kexalgos=["RSA", "DH", "ECDH", "ADH", "DHE", "AECDH", "ECDHE"]
	res=kexalgos.index(ca.kexalgo.split(" (")[0])-kexalgos.index(cb.kexalgo.split(" (")[0])
	if res!=0:
		return res
	

	#if equals, compare Diffie Hellman bit strength
	if ca.kexalgo != "RSA":
		res=int(ca.kexalgo.split("(")[1].split(" bits")[0])-int(cb.kexalgo.split("(")[1].split(" bits")[0]) #because ca and cb have the same KEX algorithm, we can compare dhbits directly
		if res != 0:
			return res

	#if equals, compare HashMAC algorithms
	hashmacalgos=["MD5", "SHA-1", "SHA-2"]
	res=hashmacalgos.index(ca.hashmacalgo)-hashmacalgos.index(cb.hashmacalgo)
	if res!=0:
		return res
	
	#if equals, compare cipher modes of operation
	modes=["CBC", "GCM"]
	res=modes.index(ca.mode)-modes.index(cb.mode)
	if res!=0:
		return res
        

def generate_csv(ciphers, fd=stdout):
	labels=column_labels.values()
	csvwriter = csv.writer(fd, delimiter=';')
	csvwriter.writerow(labels)
	for c in ciphers:
		csvwriter.writerow([c.__getattribute__(col) for col in column_labels.iterkeys()])
	csvwriter.writerow('')

"""
Merge every rows two-by-two that have only 1 field different (except for field given in parameter)
Example : 
	TLSv1.2;AES;128;CBC;DH (2048 bits);SHA-1
	and
	TLSv1.2;AES;256;CBC;DH (2048 bits);SHA-1
	will become
	TLSv1.2;AES;128 / 256;CBC;DH (2048 bits);SHA-1
Merge in place, because two rows cannot be compared after being merged, so sorting row will be impossible
"""
def merge(ciphers, do_not_merge=["cipheralgo", "sslversion"]):
	need_restart=True
	while need_restart:
		need_restart=False
		for c in ciphers:
			for other in ciphers:
				attrs=zip(c,other)
				nb_differences=0
				for (i, (ca, oa)) in enumerate(attrs):
					if ca!=oa:
						nb_differences+=1
						index_diff=attrs.index((ca,oa))
				if nb_differences==1:
					# ugly fix in order not to merge different algos in the same line
					need_to_skip=False
					for dnm in do_not_merge:
						if index_diff == Cipher._fields.index(dnm):
							need_to_skip=True
					if need_to_skip:
						continue
					# end of ugly fix
					field=Cipher._fields[index_diff]
					values=sorted([c.__getattribute__(field), other.__getattribute__(field)])
					newc_d=c._asdict()
					newc_d[field]=" / ".join(values)
					newc=Cipher(**newc_d)
					ciphers.insert(min(ciphers.index(c),ciphers.index(other)), newc)
					ciphers.remove(c)
					ciphers.remove(other)
					need_restart=True
					break
				if need_restart:
					break
			if need_restart:
				break
		
ciphers=parse_file_for_ciphers(argv[1])
ciphers=sorted(ciphers, cmp=compare_ciphers, reverse=True)
with open("ciphers_list.csv", "wb") as f:
	generate_csv(ciphers, f)
merge(ciphers, ["cipheralgo"])
with open("ciphers_list_compacted.csv", "wb") as f:
	generate_csv(ciphers, f)
