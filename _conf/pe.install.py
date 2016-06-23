if profile.test("os.shell", "cmd"):
	if profile.test("os.name", "posix"):
		Directory("bin").call(target=Resource("../bin/trupipe.cmd"))
elif profile.test("os.shell", "sh"):
	Directory("bin").execute(target=Resource("../bin/trupipe.sh"))
