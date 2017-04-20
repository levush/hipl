#!/usr/bin/env python

# Copyright (c) 2012 Aalto University and RWTH Aachen University.
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation
# files (the "Software"), to deal in the Software without
# restriction, including without limitation the rights to use,
# copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following
# conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
# OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.

_commitguard_tutorial = """
Bazaar plugin for checking code modifications at pre-commit time.

About
-----

Installation
------------
Copy this file into the Bazaar plugin directory (usually .bazaar/plugins/ in
your home directory) or add the directory this file resides in to the
environment variable BZR_PLUGIN_PATH (export BZR_PLUGIN_PATH="<dir>") before
running 'bzr commit'.

The pre-commit checks (or 'guards') are described in configuration files with
the extension .guard. This script looks for such files in two directories:
  1) $HOME/.bazaar/plugins/commitguards/
  2) <repository>/.commitguards/
This allows to set up commit guards both per user and per repository.

Usage
-----
This hook is called automatically when running the command 'bzr commit' after
the commit message has been provided. All available commit guards are then
applied to the files in the commit. If a file fails a commit guard, the
commit is aborted with an error message detailing the failure. The commit
message is printed again for convenience. A commit guard can optionally
suggest a patch to the file so that it meets the guard's requirements.

At the moment, a commit is aborted on the first failing commit guard.

Commit Guards
-------------
Commit guards are described in plain-text configuration files in .ini
style with the extension .guard. The basic format of these files is

[guard]
files=<value>
actions=<value>
command=<value>

Each guard configuration file provides three pieces of information about a
commit guard:

1) A set of filename patterns the guard is to be applied to.
   The configuration key is 'files'.
   The configuration value is a POSIX extended regular expression.
   For example, the entry 'files=\.(c|C)$' makes sure that the guard is applied
   to all files with the extension .c or .C

2) A set of commit actions specifying if the guard is to be applied to
   added, modified, and/or renamed files.
   The configuration key is 'actions'.
   The configuration value is a string consisting of one or more of the
   characters 'a', 'm', and 'r', representing added, modified, and renamed files
   respectively.
   For example, the entry 'actions=am' makes sure that the guard is applied to
   new and modified files in a commit but not to renamed files.

3) A command that is executed and which implements the actual guard action.
   The configuration key is 'command'.
   The configuration value is a string containing a shell command.
   Before executing this command, all occurrences of the substring {} are
   replaced with the name of the (added, modified, or renamed) file in the
   repository and commit to apply the guard to.
   If the guard considers the given file valid as is, the command should exit
   with an exit code of 0.
   In this case, the remaining guards are applied to the remaining files in the
   commit.
   If the guard considers a given file as invalid, it should exit with a
   non-zero exit code.
   In this case, it may print a message to stdout to inform the user why the
   commit was aborted.
   Optionally, the command may print a patch in unified diff format on stderr
   that, if applied, would bring the file into compliance with the guard's
   requirements.
   For added convenience, the commitguard plugin offers the user the option of
   applying such a patch straight away.
   Helper executables can be placed into the same directory as a .guard file.
   The guard command can then invoke these executables as if they were system
   commands.



"""

version_info = (0, 1, 0, 'dev', 0)
plugin_name = 'commitguard'

from bzrlib import branch, help_topics
import bzrlib
import subprocess
import os
import os.path
import sys
import tempfile
import re
import ConfigParser


def get_local_file_name(branch, file_name):
    """Determine the absolute path of the file in a local Bazaar working branch.

    Arguments:
    branch -- an instance of bzrlib's Branch representing a local working
    branch. file_name is resolved relative to the base location of branch.
    file_name -- a string containing the relative path of a file in the file
    tree of branch.

    This function returns a string that contains the absolute path of the
    specified file. This file is the actual on-disk working copy and can be
    accessed and modified. If file_name does not exist in branch or the
    corresponding local file cannot be found, a RuntimeError is raised.

    """
    base = branch.base
    if base.startswith('file://'):
        base = base[7:]
    local_file_name = os.path.join(base, file_name)
    if os.path.exists(local_file_name):
        return local_file_name
    else:
        raise RuntimeError("The file '%s' in branch '%s' could not be found at \
'%s' as expected!" % (file_name, branch, local_file_name))



class Guard(object):
    """A tool that inspects the new state a commit introduces and allows or
    aborts the commit.

    Each instance of this class wraps a 'guard' tool which may analyse and check
    the set of modifications of a commit. It may then let the commit pass or
    prevent it.

    """
    def __init__(self, cfg_file_name):
        """Creates and initializes a Guard object and its attributes.

        If the initialization fails, e.g., because a tool is not available or
        the configuration is invalid, an Exception is raised.

        cfg_file_name -- The path of a guard configuration file from which to
        initialize this object.

        """
        self.configure(cfg_file_name)

    def configure(self, cfg_file_name):
        """Initialize a Guard object from a configuration file.

        cfg_file_name -- The path of a guard configuration file from which to
        initialize this object.

        """
        config = ConfigParser.RawConfigParser()
        config.read(cfg_file_name)
        self.files = re.compile(config.get('guard', 'files'), re.IGNORECASE)
        self.actions = config.get('guard', 'actions')
        self.command = unicode(config.get('guard', 'command'), encoding='utf-8')
        self.filename = cfg_file_name
        self.dirname = os.path.dirname(cfg_file_name)

    def applies_to(self, file_name, file_action):
        """Checks whether this guard applies to a given file or not.

        file_name -- the name of the file in the working repository which is
        compared against this guard's file name pattern (not case sensitive).
        file_action -- one of the characters 'a', 'm', or 'r' to indicate
        whether a commit adds, modifies, or renames the given file. In the case
        of a renamed file, the file_name parameter is expected to be the new
        name of the file.

        This function returns True if the given file name and action match this
        guard and False otherwise.

        """
        return file_action in self.actions and self.files.search(file_name) is not None

    def run(self, local_file_name, action, msg, diff):
        """Execute a guard to determine whether a commit may proceed or not.

        Arguments:
        local_file_name -- the path of a local file to run the guard on. The
        guard may not modify this file.
        file_action -- one of the characters 'a', 'm', or 'r' to indicate
        whether a commit adds, modifies, or renames the given file. In the case
        of a renamed file, the local_file_name parameter is expected to be the
        new name of the file.
        msg -- a file-like object to which the guard may write a message for the
        user.
        diff -- a file-like object to which the guard may write a patch in
        unified diff format which shows how to modify the file contents in order
        to comply with this guard and let the commit proceed.

        If this function returns true, the commit may proceed. If it returns
        false, the commit is aborted.

        """
        if self.applies_to(local_file_name, action):
            cmd = self.command.replace('{}', local_file_name)
            env = os.environ
            if not self.dirname in env['PATH']:
               env['PATH'] += (':' + self.dirname)
            p = subprocess.Popen(cmd,
                                 shell = True,
                                 stdout = msg,
                                 stderr = diff,
                                 env = env)
            return p.wait() == 0
        else:
            return True


def create_guards_from_dir(cfgdir, guards):
    for wroot, wdirs, wfiles in os.walk(cfgdir):
        for f in wfiles:
            if f.endswith('.guard'):
                guards.append(Guard(os.path.join(wroot, f)))
    return guards


def create_guards(branch):
    guards = []
    cfgdirs = [os.path.join(os.path.expanduser('~'), '.bazaar/plugins/commitguards')]
    try:
        cfgdirs.append(get_local_file_name(branch, '.commitguards'))
    except:
        pass
    for cfgdir in cfgdirs:
        if os.path.exists(cfgdir):
            create_guards_from_dir(cfgdir, guards)
    return guards


def get_commit_files(tree_delta):
    """From all modifications in a commit, retrieve those files which should be
    run through the guards.

    That is: added, modified, and renamed files, ignoring meta-data changes.

    The return value is a list of tuples. Each tuple consists of a the path name
    of a file in the Bazaar repository tree as the first element and the
    character 'a', 'm', or 'r' indicating the action this commit performs on the
    file.

    """
    # include added, modified, and renamed, skip removed and changed
    files = [(path, 'a') for path, file_id, kind in tree_delta.added if kind == 'file']
    files.extend([(path, 'm') for (path, file_id, kind, text_modified, _) in
        tree_delta.modified if kind == 'file'])
    files.extend([(newpath, 'r') for (oldpath, newpath, file_id, kind, text_modified, _) in
        tree_delta.renamed if kind == 'file'])
    return files


def get_commit_message(local, master, revid):
    """Returns the commit message of a branch revision."""
    branch = local or master
    revision = branch.repository.get_revision(revid)
    return revision.message


def apply_patch(diff_file):
    """Apply a patch to a local Bazaar branch.

    diff_file -- a file-like object from which the patch can be read. The patch
    is expected to be in unified diff format.

    If applying the beautification fails, a CalledProcessError is raised.

    """
    subprocess.check_call(['patch', '-p0', '-i', diff_file.name])


def pre_commit_hook(local, master, old_revno, old_revid, future_revno,
                    future_revid, tree_delta, future_tree):
    """Run the files modified by this commit through the configured guards and
    abort the commit if the guards veto it.

    This is the pre-commit hook interface of bzrlib.

    """
    guards = create_guards(local or master)

    veto = False
    diff_file = tempfile.NamedTemporaryFile(prefix = plugin_name + "-diff-")

    for tree_file_name, action in get_commit_files(tree_delta):
        local_file_name = get_local_file_name(local or master, tree_file_name)
        for guard in guards:
            if not guard.run(local_file_name, action, sys.stdout, diff_file):
                veto = True
                break

        if veto:
            break

    if veto:
        diff_file.flush()
        if diff_file.tell():
            print "\nThe following patch is suggested so as to comply with the commit guard requirements:\n"
            diff_file.seek(0)
            print diff_file.read()
            print "\nWould you like to apply these changes to your local branch now? [y/N] ",
            reply = sys.stdin.readline()
            if reply.strip() == 'y':
                apply_patch(diff_file)
                print "Changes successfully applied.\n"
        diff_file.close()

        msg_file = tempfile.NamedTemporaryFile(prefix = 'commit-msg-%d-' % future_revno, delete = False)
        msg_file.write(get_commit_message(local, master, future_revid))
        msg_file.close()

        raise bzrlib.errors.BzrError("This commit has been aborted. The original commit message, stored in %s, was:\n--\n%s\n--" % (msg_file.name, get_commit_message(local, master, future_revid)))
    diff_file.close()


help_topics.topic_registry.register(plugin_name + '-tutorial',
                                    _commitguard_tutorial,
                                    'How to use the plugin ' + plugin_name)

branch.Branch.hooks.install_named_hook('pre_commit', pre_commit_hook,
                                       plugin_name)
