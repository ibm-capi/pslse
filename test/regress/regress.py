#!/usr/bin/python

#
# Copyright 2015 International Business Machines
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

#
# Description : mmio.c
#
# This test performs basic mmio test using the Test AFU for validating pslse
#

import getopt
import os
import random
import re
import select
import signal
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

abort = 0

def usage():
	print 'Usage: regress.py [OPTION]...'
	print ''
	print '  -c         \tforce clean compile of all code'
	print '  -d         \tforce debug compile of all code'
	print '  -b         \tbypass code compile'
	print '  -s SEED    \tseed for random number generation'
	print '  -t TEST    \tsingle test to run (Requires -x also)'
	print '  -x XML_FILE\tsingle test list file to use'
	print '  -h         \tdisplay this help message and exit'
	print ''
	sys.exit(2)

# Register stdout pipe to poll for data in ready
def register_poller(out):
	# Configure poller to trigger on data in, hangup or error
	READ_ONLY = select.POLLIN | select.POLLPRI | select.POLLHUP | select.POLLERR
	poller = select.poll()
	poller.register(out, READ_ONLY)
	return poller

# Returns true when previously registers stdout pipe has data in pending
def poller_ready(poller, process):
	# Poll for data ready and timeout in 50ms
	try:
		events = poller.poll(50)
	except:
		return False
	# Check to see if data in or priority data in is ready
	for fd, flag in events:
		if flag & (select.POLLIN | select.POLLPRI):
			return True
		if flag & select.POLLERR:
			print "Data pipe error"
			if process:
				os.kill(process.pid, signal.SIGTERM)
			sys.exit(1)
		if flag & select.POLLHUP:
			return None
	return False

# Compile code in current directory
def build(file, clean, debug):
	print('REGRESS: Building %s' % file)
	# Call 'make' to clean
	if clean or debug:
		try:
			subprocess.call(['make', 'clean'])
		except:
			print sys.exc_info()[1]
			sys.exit(1)
	# Call 'make' to build
	make_list = ['make', '-j']
	if debug:
		make_list.append('DEBUG=1')
	try:
		subprocess.call(make_list)
	except:
		print sys.exc_info()[1]
		sys.exit(1)

# Compile code and test for successful file build
def build_and_test(dir, file, clean, debug):
	# Save current directory
	cwd = os.getcwd()
	# Change directory
	os.chdir(dir)
	# Compile
	build(file, clean, debug)
	# Test for compile success
	if not os.path.isfile(file):
		print('Failed to build:%s/%s' % (os.path.dirname(os.path.realpath(__file__)), file))
		sys.exit(1)
	# Return to previous directory
	os.chdir(cwd)

# Compile code and test for successful build for all .c files in directory
def build_and_test_all(dir, name, clean, debug):
	# Save current directory
	cwd = os.getcwd()
	# Change directory
	os.chdir(dir)
	# Compile
	build(name, clean, debug)
	# Test for compile success
	for filename in os.listdir('.'):
		if filename.endswith('.c'):
			if not os.path.isfile(re.sub('.c$', '', filename)):
				print('Failed to build:%s/%s' % (os.path.dirname(os.path.realpath(__file__)), filename))
				sys.exit(1)
	# Return to previous directory
	os.chdir(cwd)

def flush_output(process, output, log):
	count = 0;
	poller = register_poller(output)
	while (poller_ready(poller, process) is True) and (count < 100):
		#print "Output ready"
		# Read next line of stdout from pslse
		out = output.readline()
		log.write(out)
		count += 1

# Start AFU devid based on desc_list attributes
def start_afu(path, afu, devid, desc_list, shim, afu_out, afu_err):
	# Initialize variables
	port = 32768
	descriptor = 'afu' + devid + '.cfg'
	running = False
	cwd = os.getcwd()

	# Create descriptor file
	desc = open (descriptor, 'w')
	for field, value in desc_list.iteritems():
		desc.write ( '%s : %s\n' % (field, value))
	desc.close();

	# Start AFU capturing stdout and stderr in pipes
	while not running and (port < 65535):
		print ("REGRESS: Attempting to start afu%s on port %d" % (devid, port))
		command = [afu, str(port), cwd + '/' + descriptor, 'parity']
		try:
			process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={'PATH': path})
		except:
			print sys.exc_info()[1]
			print('REGRESS: Failed to start afu%s' % devid)
			sys.exit(1)
		# Open log file for afu
		outname = 'afu' + devid + '.out'
		errname = 'afu' + devid + '.err'
		afu_out[devid] = open (outname, 'w', 1)
		afu_err[devid] = open (errname, 'w', 0)
		# Iterate through port numbers until successful
		afu_stdout = register_poller(process.stdout)
		afu_stderr = register_poller(process.stderr)
		while poller_ready(afu_stderr, None) is False:
			if poller_ready(afu_stdout, None) is False:
				# stdout pipe has no data ready yet
				time.sleep(0.1)
				print('Sleeping')
				continue
			out = process.stdout.readline()
			started = re.match('.*connection on .*:(.*)', out) 
			afu_out[devid].write(out)
			if started:
				port = int(started.group(1))
				print('REGRESS: Started afu%s' % devid)
				running = True
				break
			if (poller_ready(afu_stdout, None) is None) and process.poll():
				# AFU process failed to open port and stopped
				afu_out[devid].close()
				port += 1
				break
		while not poller_ready(afu_stderr, None) is False:
			out = process.stderr.readline()
			if re.match('.*Address already in use.*', out):
				# AFU process failed to open port and stopped
				afu_err[devid].close()
				port += 1
				break
			

	# Remove no longer needed descriptor file
	os.remove(descriptor)
	# Check for unsuccessful AFU start
	if (port == 65535):
		print('REGRESS: Failed to start afu%s' % devid)
		sys.exit(1)
	# Save device id and port to shim_host.dat
	shim.write ('afu' + devid + ',localhost:' + str(port) + '\n')
	return process

# Start pslse
def start_pslse(path, pslse, port, parm_list, out_log, err_log):
	# Initialize variables
	parms = 'pslse.parms'
	cwd = os.getcwd()

	# Create parms file
	parm = open (parms, 'w')
	for field, value in parm_list.iteritems():
		parm.write ( '%s:%s\n' % (field, value))
	parm.close();

	# Start pslse capturing stdout and stderr in pipes
	try:
		process = subprocess.Popen(pslse, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={'PATH': path})
	except:
		print sys.exc_info()[1]
		print "Failed to start pslse"
		sys.exit(1)
	pslse_stdout = register_poller(process.stdout)
	pslse_stderr = register_poller(process.stderr)
	while poller_ready(pslse_stderr, None) is False:
		if poller_ready(pslse_stdout, None) is None:
			# stdout pipe has closed
			print "Failed to start pslse"
			flush_output(process, process.stdout, out_log)
			out_log.close()
			flush_output(process, process.stderr, err_log)
			err_log.close()
			sys.exit(1)
		if poller_ready(pslse_stdout, None) is False:
			# stdout pipe has no data ready yet
			time.sleep(0.1)
			continue
		out = process.stdout.readline()
		started = re.match( 'INFO:Started PSLSE server, listening on .*:(.*)', out) 
		out_log.write(out)
		if started:
			port[0] = int(started.group(1))
			print 'REGRESS: Started pslse'
			break
	os.remove(parms)
	return process

def check_for_fail(process, output, log, fails):
	
	# Check output for fail message
	poller = register_poller(output)
	while poller_ready(poller, process) is True:
		#print "Output ready"
		# Read next line of stdout from pslse
		out = output.readline()
		log.write(out)
		# Check all possible fail conditions for match
		for fail in fails:
			pattern = '.*' + fail + '.*'
			if re.match(pattern, out):
				print "REGRESS:FAILED"
				print output
				return True
	return False

def run_tests(tree, test_afu_dir, test_afu_exec, pslse_dir, pslse_exec, tests_dir, test_file, seed):
	### Start AFUs
	# Open shim_host.dat
	shim = open ('shim_host.dat', 'w')
	# Parse xml test file for each afu
	root = tree.getroot()
	afu_process = {}
	afu_out = {}
	afu_err = {}
	for afu in root.findall('afu'):
		# Build desciptor hash for each afu
		desc_hash = {}
		for parm in afu:
			desc_hash[parm.tag] = parm.text
		# Get device id for afu
		afu_device = afu.get('name')
		# Start this afu
		afu_process[afu_device] = start_afu(test_afu_dir, test_afu_exec, afu_device, desc_hash, shim, afu_out, afu_err)
	# Close shim_host.dat
	shim.close()

	### Start PSLSE
	# Open pslse_server.dat
	pslse_server = open ('pslse_server.dat', 'w')
	pslse_out = open ('pslse.out', 'w', 1)
	pslse_err = open ('pslse.err', 'w', 0)
	# Parse xml test file for pslse data
	psl = root.find('pslse')
	# Build pslse parms hash
	parm_hash = {}
	pslse_port = [0]
	pslse_fail = []
	for parm in psl:
		if parm.tag == 'fail':
			# Store fail conditions seperate from other parms
			pslse_fail = parm.text.split('|')
		else:
			# Store pslse parm in hash
			parm_hash[parm.tag] = parm.text
	# Start pslse with parms from xml test file
	pslse = start_pslse(pslse_dir, pslse_exec, pslse_port, parm_hash, pslse_out, pslse_err)
	# Update and close pslse_server.dat file with pslse port
	pslse_server.write ('localhost:' + str(pslse_port[0]) + '\n')
	pslse_server.close()
	# Remove shim_host.dat that is no longer needed
	os.remove('shim_host.dat')

	### Run all tests in xml test file
	test_count = 0
	for test in root.findall('test'):
		if (test_file != '') and (test.get('name') != test_file):
			continue
		if test_file == '':
			seed = random.randint(0, 0xFFFFFFFF)
		random.seed(seed)

		# Parse parms for test
		test_parms = [test.get('name'), '--seed', str(seed)]
		for parm in test:
			test_parms.append('--' + parm.tag)
			if parm.text:
				test_parms.append(parm.text)

		# Start test and capture stdout and stderr in pipes
		test_count += 1
		passed = False
		failed = False
		print "REGRESS: Running test:",
		for parm in test_parms:
			print parm,
		print
		try:
			process = subprocess.Popen(test_parms, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={'PATH': tests_dir})
		except:
			print("REGRESS: Failed to start test '%s'" % test.get('name'))
			failed = True
			sys.exit(1)
		test_start = time.time()
		timeout = 30
		if test.get('timeout'):
			timeout = int(test.get('timeout'))

		# Search stdout for PASSED or FAILED messages
		test_out_name = test.get('name') + '.out'
		test_err_name = test.get('name') + '.err'
		test_out = open (test_out_name, 'w', 1)
		test_err = open (test_err_name, 'w', 0)
		test_stdout = register_poller(process.stdout)
		test_stderr = register_poller(process.stderr)
		counter = 0
		while not passed and not failed:
			counter += 1
			if abort:
				failed = True
				break
			if ((time.time() - test_start) > timeout):
				print 'REGRESS: Timeout'
				failed = True
				break
			if (poller_ready(test_stdout, None) is None) and process.poll():
				print("REGRESS: test '%s' terminated" % test.get('name'))
				failed = True
				break
			# Flush AFU stderr
			#print "Flushing AFU stderr"
			for dev, log in afu_err.iteritems():
				flush_output(afu_process[dev], afu_process[dev].stderr, log)
			# Flush pslse stderr
			#print "Flushing pslse stderr"
			if check_for_fail(pslse, pslse.stderr, pslse_err, pslse_fail):
				failed = True
				break
			# Flush test stderr
			if poller_ready(test_stderr, None) is True:
				#print "Flushing test stderr:%s" % line
				line = process.stderr.readline()
				test_err.write(line)
				failed = re.match( 'ERROR.*', line) 
				if failed:
					print line
				continue
			# Flush AFU stdout
			#print "Flushing AFU stdout"
			for dev, log in afu_out.iteritems():
				flush_output(afu_process[dev], afu_process[dev].stdout, log)
			# Flush pslse stdout
			#print "Flushing pslse stdout"
			if check_for_fail(pslse, pslse.stdout, pslse_out, pslse_fail):
				failed = True
				break
			# Flush test output
			if (counter % 100) and poller_ready(test_stdout, None) is True:
				line = process.stdout.readline()
				#print "Flushing test stdout:%s:" % line
				test_out.write(line)
				failed = re.match( 'FAILED.*', line) 
				passed = re.match( 'PASSED', line) 
				if failed:
					print line
				continue

		# Flush AFU and pslse stdout pipes
		for dev, log in afu_out.iteritems():
			flush_output(afu_process[dev], afu_process[dev].stdout, log)
		for dev, log in afu_err.iteritems():
			flush_output(afu_process[dev], afu_process[dev].stderr, log)
		if not failed:
			failed = check_for_fail(pslse, pslse.stdout, pslse_out, pslse_fail)
		if not failed:
			failed = check_for_fail(pslse, pslse.stderr, pslse_err, pslse_fail)

		# Close test log file
		test_out.close()
		test_err.close()

		# Report fail and exit if failed or not explicit success
		if failed or not passed:
			print("REGRESS: Test '%s' failed" % test.get('name'))
			flush_output(pslse, pslse.stdout, pslse_out)
			flush_output(pslse, pslse.stderr, pslse_err)
			pslse_out.close()
			pslse_err.close()
			for dev, log in afu_out.iteritems():
				flush_output(afu_process[dev], afu_process[dev].stdout, log)
			for dev, log in afu_err.iteritems():
				flush_output(afu_process[dev], afu_process[dev].stderr, log)
				log.close()
			os.kill(pslse.pid, signal.SIGTERM)
			sys.exit(1)

		# Test passed
		print("REGRESS: Test '%s' passed" % test.get('name'))
		if os.path.isfile(test_out_name):
			os.remove(test_out_name)
		if os.path.isfile(test_err_name):
			os.remove(test_err_name)

	# Final clean up
	for dev, log in afu_out.iteritems():
		log.close()
		logname = 'afu' + dev + '.out'
		if os.path.isfile(logname):
			os.remove(logname)
	for dev, log in afu_err.iteritems():
		log.close()
		logname = 'afu' + dev + '.err'
		if os.path.isfile(logname):
			os.remove(logname)
	pslse_out.close()
	pslse_err.close()
	os.kill(pslse.pid, signal.SIGTERM)
	return test_count

def signal_handler(signal, frame):
	abort = 1

def main(argv):

	### Default parameters
	test_afu_dir = '../afu'
	test_afu_exec = 'afu'
	pslse_dir = '../../pslse'
	pslse_exec = 'pslse'
	tests_dir = '../tests'
	bypass= 0
	clean = 0
	debug = 0
	test_file = ''
	xml_file = ''
	seed = int(time.time())

	### Parse command line
	try:
		opts, args = getopt.getopt(argv,'bcdhs:t:x:')
	except getopt.getoptError:
		usage()
	for opt, arg in opts:
		if opt == '-h':
			usage()
		elif opt == '-b':
			bypass = 1;
		elif opt == '-c':
			clean = 1;
		elif opt == '-d':
			debug = 1;
		elif opt == '-s':
			seed = int(arg);
		elif opt == '-t':
			test_file = arg;
		elif opt == '-x':
			xml_file = arg;
	if (test_file != '') and (xml_file == ''):
		print '\nERROR: Can not specify -t without -x!\n'
		usage()

	matched = re.match('^(.*)\.xml$', xml_file)
	if xml_file == '':
		print 'REGRESS: master seed = ' + str(seed)
		random.seed(seed)
	elif matched:
		xml_file = matched.group(1)

	### Register signal handler
	signal.signal(signal.SIGINT, signal_handler)

	### Compile all code
	if not bypass:
		# Compile Test AFU
		build_and_test(test_afu_dir, test_afu_exec, clean, debug)
		# Compile PSLSE
		build_and_test(pslse_dir, pslse_exec, clean, debug)
		# Compile regression tests
		build_and_test_all(tests_dir, 'regression tests', clean, debug)

	# Detect Linux
	if not re.match('^linux.*', sys.platform):
		print("REGRESS: %s can only run tests on Linux" % sys.argv[0])
		exit(-1)

	### Run through all xml file in directory
	test_count = 0
	for filename in os.listdir('.'):
		if filename.endswith('.xml'):
			if (xml_file != '') and (filename != (xml_file + '.xml')):
				continue
			tree = ET.parse(filename)
			if xml_file == '':
				seed = random.randint(0, 0xFFFFFFFF)
			random.seed(seed)
			print ("REGRESS: Running tests in '%s' with seed %d" % (filename, seed))
			test_count += run_tests(tree, test_afu_dir, test_afu_exec, pslse_dir, pslse_exec, tests_dir, test_file, seed)

	# All tests passed
	if test_count == 0:
		print 'REGRESS: No tests run!'
	elif test_count == 1:
		print 'REGRESS: Test passed'
	else:
		print 'REGRESS: All %d tests passed' % test_count
	if os.path.isfile('pslse_server.dat'):
		os.remove('pslse_server.dat')
	if os.path.isfile('gmon.out'):
		os.remove('gmon.out')
	if os.path.isfile('debug.log'):
		os.remove('debug.log')
	if os.path.isfile('pslse.out'):
		os.remove('pslse.out')
	if os.path.isfile('pslse.err'):
		os.remove('pslse.err')

if __name__ == '__main__': main(sys.argv[1:])
