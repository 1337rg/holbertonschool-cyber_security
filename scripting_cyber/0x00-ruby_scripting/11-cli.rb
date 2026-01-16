#!/usr/bin/env ruby
require 'optparse'

TASKS_FILE = 'tasks.txt'

def load_tasks
  return [] unless File.exist?(TASKS_FILE)
  File.readlines(TASKS_FILE).map(&:chomp)
end

def save_tasks(tasks)
  if tasks.empty?
    File.delete(TASKS_FILE) if File.exist?(TASKS_FILE)
  else
    File.write(TASKS_FILE, tasks.join("\n") + "\n")
  end
end

def add_task(task)
  tasks = load_tasks
  tasks << task
  save_tasks(tasks)
  puts "Task '#{task}' added."
end

def list_tasks
  load_tasks.each { |task| puts "    #{task}" }
end

def remove_task(index)
  tasks = load_tasks
  removed = tasks.delete_at(index - 1)
  save_tasks(tasks)
  puts "Task '#{removed}' removed."
end

OptionParser.new do |opts|
  opts.banner = "Usage: cli.rb [options]"

  opts.on("-a", "--add TASK", "Add a new task") do |task|
    add_task(task)
  end

  opts.on("-l", "--list", "List all tasks") do
    list_tasks
  end

  opts.on("-r", "--remove INDEX", Integer, "Remove a task by index") do |index|
    remove_task(index)
  end

  opts.on("-h", "--help", "Show help") do
    puts opts
    exit
  end
end.parse!
