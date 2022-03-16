import matplotlib
import matplotlib.pyplot as plt

from utils.utils import compare2arrays
import copy

def get_trans_graph_without_controller(tab):
	# We remove all interact transmissions
	retTab = []
	for line in tab:
		if not 'INTERACT' in line:
			toadd = line
			if ['controller'] in line:
				for i in range(len(line)):
					if toadd[i] == ['controller']:
						toadd[i] = ['sink', 'source']
			retTab.append(toadd)
	return retTab

def get_trans_graph_only_controller(tab):
	# We remove all interact transmissions
	# and keep only transmission with controller
	retTab = []
	for line in tab:
		if 'INTERACT' not in line and ['controller'] in line:
			retTab.append(line)
	return retTab

def get_app_graph(tab, isT1=False):
	# We keep only interact transmissions
	retTab = []
	for line in tab:
		if 'INTERACT' in line:
			retTab.append(line)
	return retTab


def plot_preicison_recall(x_axis, y_axis_precision, y_axis_recall, xlabel, ylabel, title, output):
	fig, ax = plt.subplots()
	precision, = ax.plot(x_axis, y_axis_precision, label='Précision', color='b')
	recall, = ax.plot(x_axis, y_axis_recall, label='Rappel', color='r')
	ax.legend(handles=[precision, recall])
	ax.set(xlabel=xlabel, ylabel=ylabel,
       	   title=title)
	ax.grid()

	fig.savefig(output)

# Compare the expected results with the set of combination for the first delta 
# of the transport graph and generate a plot of the result
# The plot shows the precision and recall for tdelta1
# Samples is a list of with the following format: {deltaValue: [result], ...}
# Return the optimal delta
def get_optimal_delta(expectedResult, samples, isT1=False, isA=False, plot:bool=False, debug=None):
	
	er = copy.deepcopy(expectedResult)

	if isT1:
		er = get_trans_graph_without_controller(er)
		xlabel = 'Delta for transport graph part 1'
		title='Precision and recall for tdelta1'
		output='tests/plot-tdelta1.png'
		debugInfo = 'Tdelta1'
	elif isA:
		er = get_app_graph(er)
		xlabel = 'Delta for application graph'
		title='Precision and recall for adelta'
		output='tests/plot-adelta.png'
		debugInfo = 'Adelta'
	else:
		xlabel = 'Delta for transport graph part 2'
		title='Precision and recall for tdelta2'
		output='tests/plot-tdelta2.png'
		er = get_trans_graph_only_controller(er)
		debugInfo = 'Tdelta2'

	if not debug is None:
		with open(debug, 'a') as outputFile:
			outputFile.write(f"{debugInfo}\n")
			outputFile.write(f"[d] - before modifications\n{expectedResult}\n")
			outputFile.write(f"[d] - after modifications\n{er}\n\n")
	
	x_axis = []           # delta
	y_axis_precision = [] # Precision rate
	y_axis_recall = []    # Recall rate
	optimal_delta = -1.
	tmp_precision = -1
	for tdelta in sorted(samples.keys()):
		falseNeg, falsePos, truePos = compare2arrays(er, samples[tdelta])
		x_axis.append(tdelta)
		precision = len(truePos) / (len(truePos) + len(falsePos))
		recall = len(truePos) / (len(truePos) + len(falseNeg))
		y_axis_precision.append(precision)
		y_axis_recall.append(recall)

		if max(tmp_precision, precision) != tmp_precision:
			tmp_precision = precision
			optimal_delta = tdelta


	if plot:
		plot_preicison_recall(x_axis, y_axis_precision, y_axis_recall, xlabel, title, output)

	return optimal_delta


def plot_controller_delta(expectedResult, samples, plot:bool=False, debug=None):
	er = copy.deepcopy(expectedResult)

	x_axis = []           # delta
	y_axis_precision = [] # Precision rate
	y_axis_recall = []    # Recall rate

	with open(debug, 'w') as outputFile:
		outputFile.write(f"delta,FN,FP,TP,Prec,Rappel\n")
		for tdelta in sorted(samples.keys()):
			falseNeg, falsePos, truePos = compare2arrays(er, samples[tdelta])
			outputFile.write(f"{tdelta},{len(falseNeg)},{len(falsePos)},{len(truePos)}\n")
			x_axis.append(tdelta)
			precision = len(truePos) / (len(truePos) + len(falsePos))
			recall = len(truePos) / (len(truePos) + len(falseNeg))
			outputFile.write(f"{tdelta},{len(falseNeg)},{len(falsePos)},{len(truePos)},{precision},{recall}\n")
			y_axis_precision.append(precision)
			y_axis_recall.append(recall)

	if plot:
		output = 'tests/controller-plot'
		title = 'Delta utilisé pour identifier les controller'
		xlabel = 'delta (seconde)'
		ylabel = 'Taux'
		plot_preicison_recall(x_axis, y_axis_precision, y_axis_recall, xlabel, ylabel, title, output)


def plot_pbc_theta(expectedResult, samples, plot:bool=False, debug=None):
	er = copy.deepcopy(expectedResult)

	x_axis = []           # delta
	y_axis_precision = [] # Precision rate
	y_axis_recall = []    # Recall rate

	with open(debug, 'w') as outputFile:
		outputFile.write(f"delta,FN,FP,TP,Prec,Rappel\n")
		for tdelta in sorted(samples.keys()):
			falseNeg, falsePos, truePos = compare2arrays(er, samples[tdelta])
			outputFile.write(f"{tdelta},{len(falseNeg)},{len(falsePos)},{len(truePos)}\n")
			x_axis.append(tdelta)
			precision = len(truePos) / (len(truePos) + len(falsePos))
			recall = len(truePos) / (len(truePos) + len(falseNeg))
			outputFile.write(f"{tdelta},{len(falseNeg)},{len(falsePos)},{len(truePos)},{precision},{recall}\n")
			y_axis_precision.append(precision)
			y_axis_recall.append(recall)

	if plot:
		output = 'tests/theta-plot'
		title = 'Theta utilisé dans le pattern PBC'
		xlabel = 'Theta (seconde)'
		ylabel = 'Taux'
		plot_preicison_recall(x_axis, y_axis_precision, y_axis_recall, xlabel, ylabel, title, output)

def plot_packet_loss(expectedResult, samples, plot:bool=False, debug=None):
	er = copy.deepcopy(expectedResult)

	x_axis = []           # delta
	y_axis_precision = [] # Precision rate
	y_axis_recall = []    # Recall rate

	with open(debug, 'w') as outputFile:
		outputFile.write(f"rate,FN,FP,TP,Prec,Rappel\n")
		for rate in sorted(samples.keys()):
			fn, fp, tp, precision, recall = 0, 0, 0, 0, 0
			for item in samples[rate]:
				falseNeg, falsePos, truePos = compare2arrays(er, item)
				fn += len(falseNeg)
				fp += len(falsePos)
				tp += len(truePos)				
				precision += tp / (tp + fp)
				recall = tp / (tp + fn)

			nbItem = len(samples[rate])
			p = precision / rate
			r = recall / rate
			fn = fn / rate
			tp = tp / rate
			fp = fp / rate
			x_axis.append(rate)
			outputFile.write(f"{rate},{fn},{fp},{tp},{p},{r}\n")
			y_axis_precision.append(p)
			y_axis_recall.append(r)

	if plot:
		output = 'tests/packet_loss-plot.png'
		title = 'Efficacité de la modélisation en fonction du taux de paquets perdus'
		xlabel = 'taux de paquets perdus (%)'
		ylabel = 'Taux'
		plot_preicison_recall(x_axis, y_axis_precision, y_axis_recall, xlabel, ylabel, title, output)