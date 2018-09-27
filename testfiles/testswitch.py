# def number_to_strings(argument):
# 	switcher = {
# 		0:"zero",
# 		1:"one",
# 		2:"two",
# 	}
# 	return switcher.get(argument, "nothing")

# res = number_to_strings(2)
# print(res)


# switcher = {
# 	"a":lambda x:x*2,
# 	"b":lambda x:x*3,
# 	"c":lambda x:x**x
# }

# try:
# 	res = switcher["b"](6)
# 	print res
# except KeyError as e:
# 	pass

class switch_case(object):

	def case_to_function(self, case):
		fun_name = "case_fun_" + str(case)
		method = getattr(self, fun_name, self.case_fun_other)
		return method

	def case_fun_1(self, msg):
		print "case_fun_1: " + msg

	def case_fun_2(self, msg):
		print "case_fun_2: " + msg

	def case_fun_other(self, msg):
		print "case_fun_other: " + msg

if __name__ == "__main__":
	cls = switch_case()
	cls.case_to_function(1)("123")
	cls.case_to_function(2)("456")
	cls.case_to_function(3)("789")