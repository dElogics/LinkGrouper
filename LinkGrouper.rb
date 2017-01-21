#! /usr/bin/ruby
# Licence: GPLv3
module LinkGrouper
	require "fileutils.rb"
	# uniqcounter is the endpoint function.
	# First arg -- Will write into a directory (plist) with it's path supplied to argument. This contains files each of which represents a class/category/group of log entries. The file is named with a random UUID.
	# 2nd arg -- A file which contains a \n separated list of absolute URLs
	# 3rd arg -- The 'groupsize'. A identified category/class/group of URLs must be of this size to be considered a category/class/group.

	require "securerandom"

	$from_sl = 1
	$to_sl = 1

	def LinkGrouper.to_slIncrement(incby)
		$to_sl = $to_sl+incby
		$to_slCaller = caller(1,1)[0].sub(/.*`([a-zA-Z]+)'$/, "\\1")
	end

	def LinkGrouper.sorted_links(flist)
		unless system("sort -r #{flist} > #{$plist + '/sorted_links'}")
			return false
		end
		return true
	end

	def LinkGrouper.bundleSlashCount(links)
		counter = nil
		links.each {
			|i|
			unless counter
				counter = i.count('/')
			end
			return false if i.count('/') != counter
		}
		true
	end

	# TODO: Existing file detection not implemented.
	def LinkGrouper.writeLinks(links, plist=$plist)
		IO.write("#{plist}/#{SecureRandom.uuid}", links.join("\n"))
	end

	# TODO:Plist 2nd argument not handled.
	def LinkGrouper.writeLink(links, plist=nil)
		links.each {
			|line|
			writeLinks([line])
		}
	end

	def LinkGrouper.nextBundle
	# 	Increment $to_sl 1 by 1 until we reach the targets. Retrieving targets.
		targets = nextBundleCalculate
	# 	no. of lines not sufficient.
		return false unless targets
		
		ctr = 1
		$from_sl, $to_sl = targets[0], targets[0]
	# 	for each added line, check if bundleSlashCount returns true for the under-creating bundle.
		while $to_sl < targets[1]
			to_slIncrement(1)
			bundledLines = bundleLines($slinksIO)
	# 		if no. of / in the newly added line differs...
			unless bundleSlashCount(bundledLines)
				writeBundledLines = Array.new
				ctr = 1
	# 			Write all the lines returned by bundleLines except the last.
				bundledLines.each {
					|i|
					while ctr < bundledLines.length
						writeBundledLines.push(i)
						ctr += 1
					end
				}
				writeLink(writeBundledLines)
				targets = nextBundleCalculate(true)
				return false unless targets
				$from_sl, $to_sl = targets[0], targets[0]
			end
		end
		true
	end

	def LinkGrouper.bundleLines(linksIO, extra=nil)
		if extra && (extra + $to_sl > $slNo)
			return nil
		end
		linesArray = Array.new
		linksIO.pos = 0
		linksIO.lineno = 0
		linescount=($to_sl - $from_sl) + 1
		linksIO.each_line {
			|line|
			line = line.chomp
			if linksIO.lineno > $to_sl + (extra == nil ? 0 : extra)
				break
			end
			if linksIO.lineno >= $from_sl
				linesArray.push(line)
			end
		}
		linesArray
	end

	def LinkGrouper.writeEnd
		if $to_slCaller == "uniqcounter"
			$from_sl = $to_sl + 1
			if $from_sl <= $slNo
				$to_sl = $slNo
				writeLink(bundleLines($slinksIO))
			end
		else
			$from_sl = $to_sl
			if $from_sl <= $slNo
				$to_sl = $slNo
				writeLink(bundleLines($slinksIO))
			end
		end
	end

	def LinkGrouper.nextBundleCalculate(overlap=nil)
	# 	check if there are enough lines remaining. If not, write the remaining lines.
		if !overlap
			if ($to_sl+1)+($groupsize - 1) > $slNo
				writeEnd
				return nil
			end
		else
			if ($to_sl)+($groupsize - 1) > $slNo
				writeEnd
				return nil
			end
		end
	# 	if it's not the initial value
		if ($from_sl != 1 || $to_sl != 1)
			from_slNext = $to_sl+1
			to_slNext = from_slNext + ($groupsize - 1)
	# 		if it is...
		else
			from_slNext = $from_sl
			to_slNext = $to_sl + ($groupsize - 1)
		end
		unless overlap
				return [from_slNext, to_slNext]
		end
	# 	For the initial values of from_sl and to_sl, this will return 0, 0 which is invalid.
		if ($from_sl != 1 || $to_sl != 1)
			return [from_slNext-1, to_slNext-1]
		else
			return nil
		end
	end

	def LinkGrouper.bundleIdnetifyGroup(links, prefix=nil)
	# 	Algo
	# 1) Identify everything before the 1st separator for the first log entry. Call this string D.
	# 2) Search for D in other logs in the same position. If even one of the log entries dont have the 1st separator, return false. If this's not the 1st time 2) is called, return the D that was common to all log entries.
	# 3) Identify the next separator, call it D and move to 2)
		if prefix
			return nil if links.grep(/^#{prefix}/).length != links.length
			return prefix
		end
		dir = nil
	# 	loop till we reach the end of the first link; i.e. everything in the 1st link was found to be common.
		while ( (dir == nil ? 0 : dir.length) != links[0].length )
	# 		identify next directory/prefix
			direscaped = nil
			direscaped = Regexp.escape(dir) if dir
			dir = links[0].sub(/^(#{direscaped}\/*[^\/]*\/*).*/, "\\1")
	# 		break if this prefix was not found in even a single link.
			(links.grep(/^#{dir}/).length != links.length) ? break : predir = dir
		end
	# 	this was the last prefix which was common for all the links.
		predir
	end
# signature -- plist (explained above), flist (input file), groupsize
	def LinkGrouper.uniqcounter(plist, flist, groupsize)
		if groupsize < 2
			return {3 => "We dont deal with groupsize below 2."}
		end
		
		unless Dir.exist?(plist)
			return {4 => "The write directory does not exist."}
		end
		
		plist = plist.chomp('/')
		
		$groupsize = groupsize
		$plist = plist
		
		linectr = 0
		IO.foreach(flist) {
			|line|
			unless line =~ /^\//
				return {1 => "Found line(s)(#{line}) which are not absolute links. Sanitize file."}
			end
			linectr += 1
		}
		$slNo = linectr
		
		unless sorted_links(flist)
# 			TODO -- Force this.
			FileUtils.rm "#{$plist}/sorted_links"
			return {2 => "sort command was not successful"}
		end
		
		$slinksIO = flistio = IO.new(IO.sysopen($plist+'/sorted_links', 'r'))
		
		while nextBundle
			bundledLines = bundleLines($slinksIO)
			bundledLinesExtra = bundledLines
			workingPrefix = nil
			testnext = 0
			while (prefix = bundleIdnetifyGroup(bundledLinesExtra, workingPrefix)) && bundleSlashCount(bundledLinesExtra)
	# bundledLines always contains lines in which a group was found. bundledLinesExtra contains the extra line which needs to be tested for an already identified prefix for the group.
				workingPrefix = prefix
				bundledLines = bundledLinesExtra
				testnext += 1
				bundledLinesExtra = bundleLines($slinksIO, testnext)
	# 			logs ran out... exit
				unless bundledLinesExtra
					writeLinks(bundledLines)
					$slinksIO.close
					FileUtils.rm "#{$plist}/sorted_links"
					return {0 => "Logs ran out while a group was identified"}
				end
			end
	#Write only if a group was found for the bundle. Also increase $to_sl to the last successfully added line.
			if workingPrefix
				writeLinks(bundledLines)
				to_slIncrement(testnext - 1)
			else
	# 			Write to individual files
				writeLink(bundledLines)
	# 			for proper functioning of writeEnd/nextBundleCalculate
				to_slIncrement(0)
			end
		end
		$slinksIO.close
		FileUtils.rm "#{$plist}/sorted_links"
		return {0 => "All done."}
	end
end