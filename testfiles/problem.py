FinalAgentIP = ['192.168.0.1','113.75.4.20']
result = {}
task_list = []
ahost = []
phost = []
i = 0
if FinalAgentIP:
    activearg = ""
    task1 = {
        "type":"activeDetection",
        #"taskArguments":"192.168.0.1/24",
    }
    task2 = {
        "type": "passiveDetection",
        # "taskArguments": "-G 600",
    }
    # task1["taskArguments"]=activearg
    print(FinalAgentIP)
    for ip in FinalAgentIP:
        print("task_list 0", task_list)
        if ahost != []:
            ahost.pop()
        if phost != []:
            phost.pop()
        ahost.append(ip + ":" + "8082")
        phost.append(ip + ":" + "8081")
        print("task_list 1", task_list)
        print("ahost:",ahost)
        print("phost:",phost)
        print("task_list 2", task_list)
        task2["taskArguments"] = "-G 600 -P " + ip
        if i == 0:
			activearg = "192.168.0.0/24"
        if i == 1:
			activearg = "113.75.0.0/16"
        
        print("task_list 3", task_list)

        task1["taskArguments"] = activearg
        task1["hosts"] = ahost
        task2["hosts"] = phost
        print("task1:", task1)
        print("task2:", task2)
        print("task list 4", task_list)
        task_list.append(task1)
        print("task list 5",task_list)
        task_list.append(task2)
        print("task list 6", task_list)
    print("task list 7", task_list)
    result["tasks"] = task_list

