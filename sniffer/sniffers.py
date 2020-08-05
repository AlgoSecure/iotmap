import multiprocessing


class Sniffer(multiprocessing.Process):
	def __init__(self, name):
		super(Sniffer, self).__init__()
		self.daemon = True
		self.exit = multiprocessing.Event()
		self.name = name

	# function to stop the process
	def terminate(self):
		self.exit.set()

	def terminated(self):
		return self.exit.is_set()
