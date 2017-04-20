# Copyright (c) 2010-2015 Aalto University and RWTH Aachen University.
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

ACLOCAL_AMFLAGS  = -I m4

HIPL_HEADER_LOCATIONS = android/ android/linux/ hipd/ hipfw/ libcore/ libcore/*/ libhipl/ modules/*/*/ test/ test/*/ test/*/*/
HIPL_HEADER_LIST = $(wildcard $(addsuffix *.h,$(addprefix $(srcdir)/,$(HIPL_HEADER_LOCATIONS))))

# For "make dist"
EXTRA_DIST  = .commitguards .dir-locals.el .uncrustify.cfg .uncrustify-0.57.cfg
EXTRA_DIST += .vimrc process_modules.py version.h
EXTRA_DIST += debian doc patches packaging tools/bazaar tools/maintainer
EXTRA_DIST += $(wildcard modules/*/module_info.xml)
EXTRA_DIST += $(wildcard $(addprefix $(srcdir)/test/libcore/,*.pem))
EXTRA_DIST += $(wildcard $(addprefix $(srcdir)/tools/,*.cfg *.pl *.sh *.xml))
EXTRA_DIST += $(wildcard $(addprefix $(srcdir)/hipfw/,*.cfg))
EXTRA_DIST += $(HIPL_HEADER_LIST)


### superuser programs ###
sbin_PROGRAMS = hipd/hipd                                               \
                tools/hipconf

if HIP_FIREWALL
sbin_PROGRAMS += hipfw/hipfw
endif


### test programs ###
noinst_PROGRAMS = test/certteststub                                     \
                  test/performance/auth_performance                     \
                  test/performance/hc_performance

if HIP_FIREWALL
noinst_PROGRAMS += test/performance/fw_port_bindings_performance
endif

if HIP_PERFORMANCE
noinst_PROGRAMS += test/performance/dh_performance
endif


### libraries ###
lib_LTLIBRARIES = libcore/libcore.la                                    \
                  libhipl/libhipl.la


### tests ###
if HIP_UNITTESTS
TESTS           = test/check_hipd                                       \
                  test/check_hipfw                                      \
                  test/check_libcore                                    \
                  test/check_libhipl                                    \
                  test/check_libcore                                    \
                  $(tools_hipdnsproxy_PYTHON)

check_PROGRAMS  = test/check_hipd                                       \
                  test/check_hipfw                                      \
                  test/check_libcore                                    \
                  test/check_libhipl
endif


### source declarations ###

test_certteststub_SOURCES                 = test/certteststub.c
test_performance_auth_performance_SOURCES = test/performance/auth_performance.c
test_performance_dh_performance_SOURCES   = test/performance/dh_performance.c
test_performance_fw_port_bindings_performance_SOURCES = hipfw/file_buffer.c    \
                                                        hipfw/line_parser.c    \
                                                        hipfw/port_bindings.c  \
                                                        test/performance/fw_port_bindings_performance.c
test_performance_hc_performance_SOURCES   = test/performance/hc_performance.c

tools_hipconf_SOURCES  = tools/hipconf.c

hipd_hipd_SOURCES = hipd/main.c

dist_sysconf_DATA = hipd/hipd.conf                                      \
                    hipd/hosts                                          \
                    hipd/relay.conf                                     \
                    hipfw/esp_prot.conf                                 \
                    hipfw/hipfw.conf                                    \
                    tools/nsupdate/nsupdate.conf

hipfw_hipfw_sources = hipfw/cache.c                                     \
                      hipfw/cert.c                                      \
                      hipfw/dlist.c                                     \
                      hipfw/esp_prot_api.c                              \
                      hipfw/esp_prot_config.c                           \
                      hipfw/esp_prot_conntrack.c                        \
                      hipfw/esp_prot_fw_msg.c                           \
                      hipfw/file_buffer.c                               \
                      hipfw/hipfw.c                                     \
                      hipfw/hipfw_control.c                             \
                      hipfw/helpers.c                                   \
                      hipfw/hslist.c                                    \
                      hipfw/line_parser.c                               \
                      hipfw/lsi.c                                       \
                      hipfw/port_bindings.c                             \
                      hipfw/reinject.c                                  \
                      hipfw/rewrite.c                                   \
                      hipfw/rule_management.c                           \
                      hipfw/user_ipsec_api.c                            \
                      hipfw/user_ipsec_esp.c                            \
                      hipfw/user_ipsec_fw_msg.c                         \
                      hipfw/user_ipsec_sadb.c

# The hipfw unit test program is linked against the hipfw object files.
# To avoid duplicate symbols during linking some object files need to excluded.
# Add all files that need to be excluded here.
hipfw_hipfw_SOURCES = $(hipfw_hipfw_sources)                            \
                      hipfw/conntrack.c                                 \
                      hipfw/midauth.c                                   \
                      hipfw/main.c

libcore_libcore_la_SOURCES = libcore/builder.c                          \
                             libcore/cert.c                             \
                             libcore/certtools.c                        \
                             libcore/checksum.c                         \
                             libcore/conf.c                             \
                             libcore/crypto.c                           \
                             libcore/debug.c                            \
                             libcore/esp_prot_common.c                  \
                             libcore/filemanip.c                        \
                             libcore/hashchain.c                        \
                             libcore/hashchain_store.c                  \
                             libcore/hashtable.c                        \
                             libcore/hashtree.c                         \
                             libcore/hip_udp.c                          \
                             libcore/hit.c                              \
                             libcore/hostid.c                           \
                             libcore/hostsfiles.c                       \
                             libcore/keylen.c                           \
                             libcore/linkedlist.c                       \
                             libcore/message.c                          \
                             libcore/modularization.c                   \
                             libcore/prefix.c                           \
                             libcore/solve.c                            \
                             libcore/state.c                            \
                             libcore/statistics.c                       \
                             libcore/straddr.c                          \
                             libcore/transform.c                        \
                             libcore/gpl/nlink.c                        \
                             libcore/gpl/pk.c                           \
                             libcore/gpl/xfrmapi.c                      \
                             modules/midauth/lib/midauth_builder.c

if !HIP_ANDROID
libcore_libcore_la_SOURCES += libcore/capability.c
else
libcore_libcore_la_SOURCES += android/ifaddrs.c
endif

if HIP_PERFORMANCE
libcore_libcore_la_SOURCES += libcore/performance.c
endif

libhipl_libhipl_la_SOURCES = libhipl/accessor.c                           \
                             libhipl/cert.c                               \
                             libhipl/close.c                              \
                             libhipl/configfilereader.c                   \
                             libhipl/cookie.c                             \
                             libhipl/dh.c                                 \
                             libhipl/esp_prot_anchordb.c                  \
                             libhipl/esp_prot_hipd_msg.c                  \
                             libhipl/esp_prot_light_update.c              \
                             libhipl/hadb.c                               \
                             libhipl/hidb.c                               \
                             libhipl/hip_socket.c                         \
                             libhipl/hipd.c                               \
                             libhipl/hiprelay.c                           \
                             libhipl/hit_to_ip.c                          \
                             libhipl/init.c                               \
                             libhipl/input.c                              \
                             libhipl/keymat.c                             \
                             libhipl/lhipl.c                              \
                             libhipl/lhipl_sock.c                         \
                             libhipl/lhipl_operations.c                   \
                             libhipl/lsidb.c                              \
                             libhipl/maintenance.c                        \
                             libhipl/nat.c                                \
                             libhipl/netdev.c                             \
                             libhipl/nsupdate.c                           \
                             libhipl/opp_mode.c                           \
                             libhipl/output.c                             \
                             libhipl/pkt_handling.c                       \
                             libhipl/registration.c                       \
                             libhipl/user.c                               \
                             libhipl/user_ipsec_hipd_msg.c                \
                             libhipl/user_ipsec_sadb_api.c                \
                             modules/cert/hipd/cert.c                     \
                             modules/heartbeat/hipd/heartbeat.c           \
                             modules/heartbeat_update/hipd/hb_update.c    \
                             modules/midauth/hipd/midauth.c               \
                             modules/update/hipd/update.c                 \
                             modules/update/hipd/update_builder.c         \
                             modules/update/hipd/update_locator.c         \
                             modules/update/hipd/update_param_handling.c

test_check_hipd_SOURCES = test/check_hipd.c                             \
                          test/hipd/lsidb.c                             \
                          test/hipd/modules/midauth.c                   \
                          $(hipd_hipd_sources)

test_check_hipfw_SOURCES = test/check_hipfw.c                           \
                           test/mocks.c                                 \
                           test/hipfw/conntrack.c                       \
                           test/hipfw/file_buffer.c                     \
                           test/hipfw/helpers.c                         \
                           test/hipfw/line_parser.c                     \
                           test/hipfw/midauth.c                         \
                           test/hipfw/port_bindings.c                   \
                           $(hipfw_hipfw_sources)

test_check_libcore_SOURCES = test/check_libcore.c                       \
                             test/libcore/cert.c                        \
                             test/libcore/checksum.c                    \
                             test/libcore/crypto.c                      \
                             test/libcore/hit.c                         \
                             test/libcore/hostid.c                      \
                             test/libcore/solve.c                       \
                             test/libcore/straddr.c                     \
                             test/libcore/gpl/pk.c                      \
                             test/libcore/modules/midauth_builder.c

test_check_libhipl_SOURCES = test/check_libhipl.c


### static library dependencies ###

hipd_hipd_LDADD                          = libhipl/libhipl.la
hipfw_hipfw_LDADD                        = libcore/libcore.la
libhipl_libhipl_la_LIBADD                = libcore/libcore.la
test_check_hipd_LDADD                    = libhipl/libhipl.la
test_check_hipfw_LDADD                   = libcore/libcore.la
test_check_libcore_LDADD                 = libcore/libcore.la
test_check_libhipl_LDADD                 = libhipl/libhipl.la
test_certteststub_LDADD                  = libcore/libcore.la
test_performance_auth_performance_LDADD  = libcore/libcore.la
test_performance_dh_performance_LDADD    = libcore/libcore.la
test_performance_fw_port_bindings_performance_LDADD = libcore/libcore.la
test_performance_hc_performance_LDADD    = libcore/libcore.la
tools_hipconf_LDADD                      = libcore/libcore.la

### dynamic library dependencies ###

test_check_hipd_LDFLAGS                  = -ldl -Wl,-z,muldefs
test_check_hipfw_LDFLAGS                 = -ldl -Wl,-z,muldefs

GENERATED_TOOLS = tools/hipdnskeyparse/hipdnskeyparse                   \
                  tools/hipdnsproxy/hipdnsproxy                         \
                  tools/nsupdate/nsupdate

dist_sbin_SCRIPTS = $(GENERATED_TOOLS)

dns_PYTHON = tools/hipdnsproxy/DNS/__init__.py                          \
             tools/hipdnsproxy/DNS/Base.py                              \
             tools/hipdnsproxy/DNS/Class.py                             \
             tools/hipdnsproxy/DNS/lazy.py                              \
             tools/hipdnsproxy/DNS/Lib.py                               \
             tools/hipdnsproxy/DNS/Opcode.py                            \
             tools/hipdnsproxy/DNS/Serialization.py                     \
             tools/hipdnsproxy/DNS/Status.py                            \
             tools/hipdnsproxy/DNS/Type.py                              \
             tools/hipdnsproxy/DNS/win32dns.py

dnsdir = $(pythondir)/DNS

tools_hipdnskeyparse_PYTHON = tools/hipdnskeyparse/myasn.py

tools_hipdnsproxy_PYTHON    = tools/hipdnsproxy/dnsproxy.py             \
                              tools/hipdnsproxy/hosts.py                \
                              tools/hipdnsproxy/util.py                 \
                              tools/hipdnsproxy/resolvconf.py           \
                              tools/hipdnsproxy/resolvconf_test.py      \
                              tools/hipdnsproxy/dnsproxy_test.py

tools_hipdnskeyparsedir = $(pythondir)/hipdnskeyparse
tools_hipdnsproxydir    = $(pythondir)/hipdnsproxy


### misc stuff ###

# This is supposed to be a sanity check target to run before pushing changes
# to the world at large. It should catch a number of easily-avoidable mistakes.
alltests: doxygen checkheaders check distcheck

# Trigger Make errors on any output to stderr, under the assumption that it is
# Doxygen warnings. This is a poor man's emulation of -Werror for Doxygen.
doxygen: doc/Doxyfile
	{ doxygen $< 2>&1 1>&3 | { ! grep . ; } ; } 3>&1

if HAVE_XMLTO
nodist_doc_DATA = doc/HOWTO.html $(wildcard $(addprefix $(srcdir)/doc/,*.png))
# xmlto text conversion depends on w3m
if HAVE_W3M
nodist_doc_DATA += doc/HOWTO.txt
endif
endif

doc/HOWTO.html:  doc/HOWTO.xml
	xmlto -o $(@D) html-nochunks $<

doc/HOWTO.txt: doc/HOWTO.xml
	xmlto -o $(@D) txt $<

CLEANFILES = doc/HOWTO.html doc/HOWTO.txt
clean-local:
	rm -rf doc/doxy rpmbuild

bin deb rpm syncrepo syncrepo_deb syncrepo_rpm: $(srcdir)/version.h
	@srcdir@/packaging/create-package.sh $@

docker-ubuntu-bin-syncrepo: dist
	cp hipl-*.tar.gz @srcdir@/packaging/docker/ubuntu/
	@srcdir@/packaging/docker/ubuntu/build-and-run.sh

autotools-clean: maintainer-clean
	rm -f aclocal.m4 compile config.* configure depcomp install-sh
	rm -f ltmain.sh m4/*.m4 Makefile.in missing py-compile

HIPL_HEADER_OBJS     = $(subst $(srcdir),$(builddir),$(HIPL_HEADER_LIST:.h=.ho))
CLEANFILES          += $(HIPL_HEADER_OBJS)
DISTCLEANFILES       = $(wildcard modules/*.h)

$(HIPL_HEADER_OBJS): $(BUILT_SOURCES)
checkheaders: $(HIPL_HEADER_OBJS)
vpath %.h $(srcdir)
%.ho: %.h
	$(AM_V_CC) $(CC) -I$(srcdir) -I$(builddir) $(AM_CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -o $@ $<

BUILT_SOURCES = version.h
$(srcdir)/version.h: $(wildcard $(srcdir)/.bzr/checkout/dirstate)
	bzr version-info $(srcdir) --custom --template='#define VCS_REVISION "{revno}"\n#define VCS_DATE "{date}"\n#define VCS_BRANCH "{branch_nick}"\n' > $@


# Files that are generated by configure should not be distributed.
dist-hook:
	rm -f $(addprefix $(distdir)/doc/,Doxyfile HOWTO.xml)
	rm -rf $(distdir)/doc/doxy
	rm -f $(addprefix $(distdir)/,$(GENERATED_TOOLS))
	rm -f $(distdir)/debian/hipl-dnsproxy.install
	rm -f $(distdir)/packaging/openwrt/hipl/Makefile

.PHONY: alltests bin checkheaders deb doxygen rpm syncrepo*
