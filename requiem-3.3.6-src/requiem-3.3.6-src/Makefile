JAVASOURCES = $(wildcard *.java)
CSOURCES = $(wildcard *.c *.cc bigint/B*.cc)
CHEADERS = $(wildcard *.h)

ifeq ($(shell uname),Darwin)

RELEASE = requiem-3.3.6-mac

MAC_JAVASOURCES = $(filter-out WindowsConfig.java, $(JAVASOURCES))
$(RELEASE).zip: $(JAVASOURCES) $(CSOURCES) $(CHEADERS)
	javac -target 1.5 $(MAC_JAVASOURCES)
	g++ -m32 -mmacosx-version-min=10.5 -O3 -I/System/Library/Frameworks/JavaVM.framework/Headers -dynamiclib -framework ApplicationServices -o libNative32.dylib MacConfig.cc
	g++ -m64 -mmacosx-version-min=10.5 -O3 -I/System/Library/Frameworks/JavaVM.framework/Headers -dynamiclib -framework ApplicationServices -o libNative64.dylib MacConfig.cc
	g++ -DWINDOWS=0 -m32 -mmacosx-version-min=10.5 -O3 extractor.cc x86sim.cc simphone.cc aes.c tables.cc $(wildcard bigint/B*.cc) -o extractor
	jar cf Requiem.jar *.class libNative32.dylib libNative64.dylib extractor CoreFP-1.13.35.x86 CoreFP1-1.13.35.x86 CoreFP-1.13.35.icxs CoreFP1-1.13.35.icxs
	ant -f macbuild.xml bundle
	rm -fr $(RELEASE) $(RELEASE).zip
	mkdir $(RELEASE)
	cp README $(RELEASE)
	cp -r Requiem.app $(RELEASE)
	zip -r $(RELEASE).zip $(RELEASE)

else

RELEASE = requiem-3.3.6-win

WIN_JAVASOURCES = $(filter-out MacConfig.java, $(JAVASOURCES))
$(RELEASE).zip: $(JAVASOURCES) $(CSOURCES) $(CHEADERS)
	javac -target 1.5 $(WIN_JAVASOURCES)
	g++ -m32 -O3 -mno-cygwin "-I$(JAVA_HOME)/include" "-I$(JAVA_HOME)/include/win32" -Wl,--add-stdcall-alias -shared -o Native32.dll WindowsConfig.cc md5.c
	x86_64-w64-mingw32-g++ -m64 -O3 -mno-cygwin "-I$(JAVA_HOME)/include" "-I$(JAVA_HOME)/include/win32" -Wl,--add-stdcall-alias -shared -static-libgcc -static-libstdc++ -o Native64.dll WindowsConfig.cc md5.c
	g++ -DWINDOWS=1 -m32 -O3 -mno-cygwin extractor.cc x86sim.cc winphone.cc aes.c tables.cc $(wildcard bigint/B*.cc) -o extractor
	jar cf Requiem.jar *.class Native32.dll Native64.dll extractor CoreFPWin-1.13.37.x86
	ant -f winbuild.xml -v bundle
	rm -fr $(RELEASE) $(RELEASE).zip
	mkdir $(RELEASE)
	cp README $(RELEASE)
	cp -r Requiem.exe $(RELEASE)
	zip -r $(RELEASE).zip $(RELEASE)

endif

SRCRELEASE = requiem-3.3.6-src
$(SRCRELEASE).zip: $(JAVASOURCES) $(CSOURCES) $(CHEADERS)
	rm -fr $(SRCRELEASE) $(SRCRELEASE).zip
	mkdir $(SRCRELEASE)
	cp -r *.java *.cc *.c *.h bigint CoreFP-1.13.35.x86 CoreFP1-1.13.35.x86 CoreFP-1.13.35.icxs CoreFP1-1.13.35.icxs CoreFPWin-1.13.37.x86 Makefile README macbuild.xml winbuild.xml requiem.icns requiem.ico $(SRCRELEASE)
	rm -fr $(SRCRELEASE)/bigint/CVS
	zip -r $(SRCRELEASE).zip $(SRCRELEASE)

all:	$(RELEASE).zip $(SRCRELEASE).zip

clean:
	rm -fr *~ *.class libNative32.dylib libNative64.dylib Native32.dll Native64.dll Requiem.jar Requiem.app $(RELEASE) $(RELEASE).zip $(SRCRELEASE) $(SRCRELEASE).zip
