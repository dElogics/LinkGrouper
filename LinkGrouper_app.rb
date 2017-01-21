#! /usr/bin/ruby
# An app using the module. Not tested.
# First arg -- Will write into a directory (plist) with it's path supplied to argument. This contains files each of which represents a class/category/group of log entries. The file is named with a random UUID.
# 2nd arg -- A file which contains a \n separated list of absolute URLs
# 3rd arg -- The 'groupsize'. A identified category/class/group of URLs must be of this size to be considered a category/class/group.
require Dir.pwd + "/LinkGrouper.rb" 
LinkGrouper.uniqcounter(ARGV[0], ARGV[1], ARGV[2])