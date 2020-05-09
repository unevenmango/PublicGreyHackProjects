version = "1.0.0"
creator = "UnevenMango"

TEST = function(thing)
	print("type: " + typeof(thing))
	print("Print: -=" + thing + "=-")
	len = null
	if thing then 
		len = thing.len
	end if
	print("len: " + len)
end function


color = { "WHITE":"<color=#FFFFFF>","PURP":"<color=#8C00FF>","CYAN":"<color=#009FED>","ERROR": "<color=#FF0000>", "SUCCESS": "<color=#24FF00>", "INFO": "<color=#ED8102>","END":"</color>" }
color.text = function(hex, text)
	//if not hex[0] == "#" then hex = "#" + hex end if
	if not hex.len == 15 then print(text) end if
	return hex + text + color.END
end function
color.print = function(hex, text)
	return print(color.text(hex, text))
end function

Core = {"option":""}



File = function(filePath,shell="null")
	if shell == "null" then shell = get_shell
	file_path = filePath[:filePath.lastIndexOf("/")] +"/"
	file_name = filePath[filePath.lastIndexOf("/")+1:]
	file = shell.host_computer.File(file_path+file_name)
	if not file then
		create = shell.host_computer.touch(file_path,file_name)
		if create == 1 then
			file = shell.host_computer.File(file_path+file_name)
			if not file.has_permission("r") then exit(color.text(color.ERROR," Failed to run... chmod on "+file.name+" is preventing start"))
		else 
			exit(file_path+file_name + " file failed to be ceated ")
		end if
	end if
	return file
end function

KVload = function(file)
	content = file.content
	map = {}
	current = ""
	for line in content.split("\n")
		if line != "" then
			if line[0] == " " then
				map[current][line.split(":")[0].trim] = line.split(":")[1]
			else
				current = line
				if not map.hasIndex(current) then map[current] = {}
			end if
		end if
	end for
	return map
end function

KVsave = function(m)
	//Dat
	output = ""
	for kv in m
		for v in kv.value
			output = output + v.key + "\n"
			for k in v.value
				k.key
				output = output + "    " + k.key + ":" + k.value + "\n"
			end for
		end for
		save = File(PayloadsFile.path + "/" + kv.key)
		save.set_content(save.content + output)
	end for
end function
//main
PayloadsFile = get_shell.host_computer.File(home_dir + "/Dat")
if not PayloadsFile then 
	get_shell.host_computer.create_folder(home_dir+"/","Dat")
	PayloadsFile = get_shell.host_computer.File(home_dir + "/Dat")
end if
Core.Payloads = {}
for file in PayloadsFile.get_files
	Core.Payloads[file.name] = file
end for
//main

Lib_load = function(name)
	Lib = include_lib("/lib/"+name)
	if not Lib then
		Lib = include_lib("/root/"+name)
		if not Lib then Lib = include_lib("/home/guest/"+name)
		if not Lib then exit("<color=#ff0000>"+Lib+" missing Error or Missing File </color>\nUnable to locate "+name+"\n")
	end if
	return Lib
end function

creator = ["U","n","e","v","e","n","M","a","n","g","o"]

Scanner = {"metaxploit":Lib_load("metaxploit.so")}

Scanner.data = {}

Scanner.init = function()
    color.print(color.INFO,"Initializing Scanner")
	self.ip = profile.ip
    print("ip set : " + self.ip)
	self.option = Core.option
	self.AllPorts = []
end function
Scanner.localLib = function()

end function
Scanner.run = function()
    
	self.init
    
	self.router = get_router(self.ip) 

	self.lan_ips = self.router.computers_lan_ip
	self.Network = {}
	comps = self.lan_ips.len
	MetaList={}
	for lan_ip in self.lan_ips
		
		profile.computers[lan_ip] = {} //add to profiile
		
		Ports = self.router.computer_ports(lan_ip)
		Ports = Ports + [{"is_closed":1,"get_lan_ip":lan_ip,"port_number":0,"classID":"Port"}]
		for Port in Ports
            metaLib = null
			LAN = Port.get_lan_ip
			if not self.Network.hasIndex(LAN) then self.Network[LAN] = {}
			NUM = Port.port_number
			INFO = self.router.port_info(Port)
			if not INFO then INFO = "null null"
			X = "Open"
			if Port.is_closed then X = "Closed"
            if profile.port == "all" or profile.port == NUM then metaLib = self.getPortlib(Port)

			if not metaLib then 
				metaLib = {"lib_name":INFO.split(" ")[0],"version":INFO.split(" ")[1]}
			else
				MetaList[metaLib.lib_name + "_" + metaLib.version] = metaLib
				metaLib = {"lib_name":color.text(color.SUCCESS, metaLib.lib_name),"version":color.text(color.SUCCESS, metaLib.version)}
			end if
			self.Network[LAN][NUM] = {"info":INFO,"status":X,"metaLib":metaLib.lib_name + "_" + metaLib.version}
		end for
	end for
    print("scan complete")
	return MetaList
   
end function

fill = function(sim,mintext="") //full line of sim
	single = sim
	for i in range(0,61-mintext.len)
		sim = single + sim
	end for
	return mintext+sim
end function

space = function(num,txt)
	output = ""
	while num > 0
		output = output + " "
		num = num - 1
	end while
	return output + txt
end function

Scanner.getPortlib = function(port = "null")
	
	net_session = self.metaxploit.net_use(self.ip, port.port_number) ////scanport
	if not net_session then 
		color.print(color.ERROR,"Net_Session Error on port : " + port.port_number)
		return
	end if
	metaLib = net_session.dump_lib
	self.metaLibScan(metaLib)
	return metaLib
	
end function

///######################################################################

Scanner.metaLibScan = function(metaLib)
	//print("searching..."+Core.Payloads.indexes)
	if Core.Payloads.hasIndex(metaLib.lib_name+"_"+metaLib.version) then
		//print("Found save")
		self.data[metaLib.lib_name+"_"+metaLib.version] = KVload(Core.Payloads[metaLib.lib_name+"_"+metaLib.version]) //load payloads
		return
	else if self.data.hasIndex(metaLib.lib_name+"_"+metaLib.version) then
		return
	end if
	print(color.text(color.INFO,"Discoverd: ") + color.text(color.WHITE, metaLib.lib_name+"_"+metaLib.version))
	print("Scanning For Vulnerabilities...")
	self.data[metaLib.lib_name+"_"+metaLib.version] = self.scan_parser(metaLib)
	KVsave(self.data)
end function

Scanner.scan_parser = function(metaLib)
	allexp = {}
	scan = self.metaxploit.scan(metaLib)
	i=0
	Raw = ""
	output = metaLib.lib_name+"_"+metaLib.version + "\n"
	for entry in scan
		i=i+1
		memory_scan = self.metaxploit.scan_address(metaLib, entry)
		output = output + memory_scan
		self.list_data = memory_scan.split("\n")
		for line in self.list_data
			index = self.list_data.indexOf(line)
			extract = line[line.indexOf("<b>")+3:line.indexOf("</b>")]
			if extract then
				allexp = allexp + self.specifyBold(extract)
			end if
		end for
	end for
	output = output + "\n==========================================================\n"
	scanLibtxt = File(home_dir+"/Dat/scanlib.txt")
	scanLibtxt.set_content(scanLibtxt.content + metaLib.lib_name+"_"+metaLib.version + "\n" + output + "\n\n")
	return allexp
end function

Scanner.specifyBold = function(extract)
	values = {}
	if extract.indexOf(".") == null then 
		values[entry + "@" + extract] = {}
		c=1
		req = ""
		while self.list_data[index+c].indexOf("*") != null
			req = self.list_data[index+c] + req
			if req == "" or not req then req = "N/A"
			c=c+1
		end while
		values[entry + "@" + extract]["req"] = req + "."
		values[entry + "@" + extract]["res"] = "Unknown"
	end if
	return values
end function

Scanner.display = function()
	
	color.print(color.CYAN,"essid : " + self.router.essid_name)
	color.print(color.CYAN,"bssid : " + self.router.bssid_name)
	prt = ""
	for line in whois(self.ip).split("\n")
		prt = prt + "<b>" + line.split(":").join(":</b>") + "\n"
	end for
	prt = prt + fill("-") + "\n"
	for lan_ip in self.Network	
		
		prt = prt + color.text(color.WHITE,fill("-",lan_ip.key + "  ")) + "\n"
		
		for port in lan_ip.value
			
			prt = prt +color.text(color.WHITE,space(profile.ip.len,"|-")) + port.key + " [" + port.value.status + "] " + port.value.metaLib + " " + "\n"
			
		end for
	end for
	print(prt)
	
end function
scanner = new Scanner
PayloadCheck = function(metaname)
	req=0
	s=0
	c=0
	f=0
	for exploit in scanner.data[metaname]
		if exploit.value.res != "Unknown" and exploit.value.res  != "null" then 
			if exploit.value.res == "shell" then s=s+1
			if exploit.value.res == "computer" then c=c+1
			if exploit.value.res.indexOf("_") or exploit.value.res == "file" then f=f+1
		end if
		if exploit.value.req == "." then req=req+1
	end for
	if req > 0 then 
		req = color.text(color.CYAN,req)
	else
		req = color.text(color.ERROR,req)
	end if	
	if s > 0 then s = color.text(color.SUCCESS,s)
	if c > 0 then c = color.text(color.SUCCESS,c)
	if f > 0 then f = color.text(color.SUCCESS,f)
	return {"ires":"<S:"+s+"/C:"+c+"/F:"+f+">","ireq":"NoReq:"+req}
end function

q = """"

Reshandle = "if not res then exit("+q+"failed"+q+")\nshell=null\nprint("+q+"<b>Revieved: "+q+"+typeof(res))\nif typeof(res) == "+q+"computer"+q+" then search.Auto(res)\nif typeof(res) == "+q+"file"+q+" then search.Auto(res)\nif typeof(res) == "+q+"shell"+q+" then\nshell = res\nsearch.Auto(shell.host_computer)\nend if\n"
Reshandle = Reshandle + "get_shell.host_computer.touch(home_dir,"+q+"PassOutput.txt"+q+")\npassfile = get_shell.host_computer.File(home_dir +"+q+"/PassOutput.txt"+q+")\nfor file in search.passFileList\nprint(""saveing : ""+file.name )\n"
Reshandle = Reshandle + "passfile.set_content(passfile.content +"+q+"##################"+q+"+ file.name +"+q+"##################"+q+"+ file.content)\nprint(file.content)\n"
Reshandle = Reshandle + "end for\nif shell then\nuser_input("+q+"Recieved shell! CTRL-c to exit/ enter to Connect"+q+")\nshell.start_terminal\nelse\nprint("+q+"Unable to Obtain shell"+q+")\nend if\n"
    //if not file.hasIndex(""content"") then continue\n
searchfunc = "Search = {}\nSearch.passFileList = []\n"
searchfunc = searchfunc + "Search.Auto = function(comp)\nself.passFileList = []\nif typeof(comp) == "+q+"computer"+q+" then comp = comp.File("+q+"/"+q+")\nself.current = comp\nself.current_folder = self.current\nself.searchFolder\nend function\n"
searchfunc = searchfunc + "Search.searchFolder = function()\nfor FF in self.current.get_folders+self.current.get_files\nself.current = FF\nif self.current.is_folder then \nself.searchFolder \nend if\n"
searchfunc = searchfunc + "if not self.current.is_binary then\nif self.current.content then\nif self.current.content.indexOf("+q+":"+q+") != null then\nself.passFileList.push(self.current)\nif self.current.name ==" +q+"passwd"+q+ "then print("+q+"etc password file found"+q+")\n"
searchfunc = searchfunc + "end if\nend if\nend if\nend for\nend function\nsearch = new Search\n"

adjectives1 = ["The Pearl Of Justice,","Imaculate","Unreal","Inconceivable","Artistic","My Precious",color.text(color.ERROR,"RedHat"),color.text(color.INFO,"Mango Powered")]
adjectives = adjectives1 + ["Adorable","Delightful","Homely","Quaint","Adventurous","Depressed","Horrible","Aggressive","Determined","Hungry","Real","Agreeable","Different","Hurt","Relieved","Alert","Difficult","Repulsive","Alive","Disgusted","Ill","Rich","Amused	","Distinct","Important","Sick","Angry","Disturbed","Impossible","Scary","Annoyed","Dizzy","Inexpensive","Selfish","Annoying","Doubtful","Innocent","Shiny","Arrogant","Exuberant","Lucky","Tame","Breakable","Faithful","Gorgeous"]
Simplelocal = "passChg = function(m,extract)\nPas=""jumpman""\nres=l.overflow(m,extract,Pas)\nif res == 1 then print(""<b>Password change Success: ""+Pas+""</b>"")\nend function\npp=program_path\nres=null\nM=include_lib(pp[:pp.lastIndexOf(""/"")+1]+""metaxploit.so"")\nif not M then exit(""metaxploit.so is missing"")\nif params.len > 0 then\nif params[0].indexOf(""/"") != null then \nl=M.load(params[0])\nelse\nl=M.net_use(get_router.public_ip).dump_lib\nend if\nif not l then exit(""grabLib FAILED"")\nfor m in M.scan(l)\nfor line in M.scan_address(l,m).split(""\n"")\nextract = line[line.indexOf(""<b>"")+3:line.indexOf(""</b>"")]\nif extract then\nif extract.indexOf(""."") == null then \nif params[0].indexOf(""/"") != null then \nres=l.overflow(m,extract)\nif not res then \nres=l.overflow(m,extract,get_router.local_ip)\npassChg(m,extract)\nend if\nelse\nres=l.overflow(m,extract,params[0])\nend if\n\nif typeof(res) == ""file"" then search.Auto(res)\nif typeof(res) == ""shell"" then search.Auto(res.host_computer)\nif typeof(res) == ""computer"" then search.Auto(res)\nif typeof(res) == ""shell"" then\nQ=user_input(res.host_computer.current_path+"" Ready to enter?y"")\nif Q == ""y"" then res.start_terminal\nend if\nend if\nend if\nend for\nend for\nelse\nprint(""[lan_ip] or [LibPath]"")\nend if\n"
Simplelocal = searchfunc + Simplelocal + Reshandle
    
NetExploit = function()
    NOREQ = []

    for libname in scanner.data
        for exploit in libname.value
            if exploit.value.req == "." then NOREQ.push({"exploit":exploit.key,"libname":libname.key})
        end for
    end for
    if NOREQ.len == 0 or module.var.SEL.to_int then 
		
		print("No "+adjectives[floor(rnd * adjectives.len)] + " Exploits found Please select your own")
		user_input("enter")
        libname = select(scanner.data)
        if not libname then exit
        if libname == "q" then exit
        exploit = select(scanner.data[libname],2)
        if not exploit then exit
        if exploit == "q" then exit
        NOREQ = [{"exploit":exploit,"libname":libname}]
    else
        s = ""
        if NOREQ.len > 1 then s = "s"

      	word = floor(rnd * adjectives1.len)
        color.print(color.SUCCESS,"Createing " + adjectives1[word] + " Exploit"+s)
    end if

    for freebe in NOREQ
        nameList = freebe.exploit.split("@")
		router = false
        name = ""
        for i in range(0,floor(rnd * nameList[0].len)/2)
            letter1 = floor(rnd * nameList[1].len)
            letter2 = floor(rnd * nameList[0].len)
            chance = floor(rnd * nameList[0].len)
            name = name + nameList[1][letter1] + nameList[0][letter2]
            if chance then i = i-1
        end for
        libname = freebe.libname
        libversion = libname[libname.lastIndexOf("_"):]
        libname = libname.replace(libversion,"").replace("lib","").replace(".so","").replace("kernel_","")
        name = libname + name
        word = floor(rnd * adjectives.len)
        req = ""
        color.print(color.CYAN,"Constructing: " + adjectives[word] + " " + name)
        instr = "[ip] [port]"
        paramlen = 2
        if libname == "router" then 
            instr = "[ip] [lan_ip]"
            router = true
        end if
        Exploit = "help = function()\nprint("+q+name+" - usage "+instr+q+")\nprint("+q+"Exploits on " + libname +"      Version number: "+libversion[1:] + " "+ req + q +")\nprint("+q+creator.join("")+q+")\nend function\n"
        Exploit = Exploit + "if params.len < "+paramlen+" then exit(help)\n"
        Exploit = Exploit + searchfunc
        Exploit = Exploit + "metaxploit = include_lib("+q+"/lib/metaxploit.so"+q+")\nif not metaxploit then metaxploit = include_lib(home_dir + "+q+"/metaxploit.so"+q+")\nif not metaxploit then exit("+q+"Metaxploit Cant be found"+q+")\n"
        NU = "params[0], params[1].to_int"
        if router then NU = "params[0], 0"
        Exploit = Exploit + "net_session = metaxploit.net_use("+NU+")\nif not net_session then exit("+q+"net_session Error: Invalid ip or port"+q+")\nmetalib = net_session.dump_lib\n"
        rout = ""
        if router then rout = ", params[1]"

        Exploit = Exploit + "res = metalib.overflow("+q+nameList[0]+q+", "+q+nameList[1]+q+rout+")\nif params.len == 3 then res = metalib.overflow("+q+nameList[0]+q+", "+q+nameList[1]+q+rout+", params[2])\n"
        
        Exploit = Exploit + Reshandle
        tmp = File(home_dir+"/"+name+".src")
        tmp.set_content(Exploit)
        get_shell.build(home_dir+"/"+name+".src", module.var.PATH)
		if get_shell.host_computer.File(module.var.PATH +"/"+name) then 
			color.print(color.SUCCESS,"Script Created! " + tmp.content.split("\n").len + " lines built")
        	if module.var.DEL.to_int then tmp.delete
		else
			color.print(color.ERROR,"An ERROR has Ocerred. Dumping script...\n   avoiding deletion")
			print(Exploit)
			color.print(color.ERROR,"Script FAILED to build!")
		end if

    end for

end function
formatPayload = function(l, i)
	out = null
	if l[i].hasIndex("res") then
		out = " "+l[i].res + "\n    " + l[i].req.replace(".*","\n    *")
	end if
	return out
end function

Cypher = {}
AllPassword = File(home_dir+"/Dat/"+"mxfw.pass")
Cypher.metaLib = Lib_load("crypto.so")
Cypher.checkHash = function(hash)
	HashStore = File(home_dir + "/Dat/HashFile").content
	HashStoreList = HashStore.split("\n")
	
	for hashed in HashStoreList
		if hashed.len > 10 then 
			if hashed.split(":")[1] == hash.split(":")[1] then return hashed.split(":")[0]
		end if
	end for
	return
end function

Cypher._dec = function(pass)
	if pass.indexOf(":") == null then return 
	
	cracked_pass = self.checkHash(pass)
	if cracked_pass then 
		color.print(color.SUCCESS,"Password for " + pass.split(":")[0] + " >> " + cracked_pass)
		AllPassword.set_content(AllPassword.content + "\n" + pass.split(":")[0] + ":" + cracked_pass)
		return cracked_pass
	end if
	cracked_pass = self.metaLib.decipher(pass.split(":")[0],pass.split(":")[1])
	if cracked_pass then 
		AllPassword.set_content(AllPassword.content + "\n" + pass.split(":")[0] + ":" + cracked_pass)
		PassFileStore = File(home_dir + "/Dat/HashFile")
		PassFileStore.set_content(PassFileStore.content + cracked_pass + ":"+ pass.split(":")[1]+ "\n")
		color.print(color.SUCCESS,"Password for " + pass.split(":")[0] + " >> " + cracked_pass)
		return cracked_pass
	end if
	color.print(color.ERROR,"Password not found :'(")
	return 
end function

formatselect = function(list,option) //display payloads
	prt = ""
	for item in list
		i=i+1
		
		if typeof(item) == "file" then
            prt = prt + formatfile(item)
		else if typeof(item) == "map" then
				info = formatPayload(list, item.key) + "\n"

				if not info then info = " /Data/[" + item.value.len +"]\n"

				if scanner.data.hasIndex(item.key) then 
					abc = PayloadCheck(item.key)
					info = "["+list[item.key].len+"] "+abc.ireq + " " + abc.ires + "\n"
				end if

				prt = prt + color.text(color.WHITE,"["+i+"] ") + color.text(color.SUCCESS,item.key) + info + "\n"

		else if typeof(item) == "string" then
			if item.len < 15 then 
				NNN = "\n"

				prt = prt + color.text(color.INFO,i+"..") + color.text(color.SUCCESS,item) + "/Opt "+NNN
			else
				prt = prt + color.text(color.INFO,i+"..") + color.text(color.SUCCESS,item) + "\n"
			end if
		end if

	end for
	return prt
end function

select = function(list,option=0)
	user="nul"
	i=0
	dot = "<u>- - - - - - - - - - - - - - - - - - - - - - - - - - - - - -</u>"
	print(dot)
	//if SORT then list = list.sort
	if option > 0 then
		print(formatselect(list,option))
	else
		print(format_columns(formatselect(list,option)))
	end if
	print(dot.remove("<u>"))
	while user.to_int > list.len
		user = user_input("[1 - "+list.len+"/'q'] > ")
		
		if user == "" then return
		if user == "0" then return
		if user == "q" then return "q"

	end while
	
	if typeof(list) == "map" then 
		return list.indexes[user.to_int-1]
	end if
	return list[user.to_int-1]
end function

libpeter = function() ///pan: put exploits on one line and send to this to load
	//LocalExploits = File("exploits")
	//map = {}
	//mkey = k.split("!")[0]
	//map[mkey] = {}
	//kvs = k[(mkey.len + 1):].split("#")
	//for kv in kvs
	//	map[mkey][kv.split(":")[0]] = kv.split(":")[1]
	//end for
	file = File(home_dir+"/"+"localLibExploit.src")
	file.set_content(Simplelocal)
	get_shell.build(file.path,home_dir)
	if File(home_dir+"/"+"localLibExploit") then 
		color.print(color.SUCCESS, "localLibExploit script buildt")
		file.delete
	else
		color.print(color.ERROR, "localLibExploit failed to build")
	end if

end function


mtpeter = function()

	Filename = module.var.NAME
	recUser = module.var.USER
	recPass = module.var.PASS
	Location = module.var.PATH
	recIp = profile.ip
	recPort = profile.port
	if recUser == "" then recUser = "root"
	service = null
	if recPort == 21 then service = "ftp"
	if recPort == 22 then service = "ssh"
	if not service then user_input("Service type[ssh/ftp] : ")
	remcomp = get_shell.connect_service(recIp,recPort,recUser,recPass,service)
	if not remcomp then return color.print(color.ERROR, "Unable to Connect to Server ")
	scr = searchfunc
	scr = scr + "comp = get_shell.host_computer\nsearch.Auto(comp)\nip = get_router.public_ip\nuser = active_user\n"
	scr = scr + "all ="+q+q+"\nfor file in search.passFileList\nall = all +"+q+"<b>"+q+"+file.name+"+q+"</b>"+q+" + file.content\nend for\n"
	scr = scr + "remote = get_shell.connect_service("+q+recIp+q+","+recPort+","+q+recUser+q+","+q+recPass+q+","+q+service+q+")\nif not remote then exit("+q+"all else failed, pack it up boys we are going home"+q+")\n"
	scr = scr + "remote.host_computer.touch("+q+Location+q+","+q+recIp+".bukit"+q+")\nremote.host_computer.File("+q+Location+q+"+"+q+"/"+q+"+"+q+recIp+".bukit"+q+").set_content(all)\n"
	file = File(home_dir+"/"+Filename)
	file.set_content(scr)

end function

varshare = function(var,modvar)
	for val in var
		if modvar.hasIndex(val.key) then modvar[val.key] = var[val.key]
	end for
	return modvar
end function
runscanner = function()
    scanner.run
    scanner.display
end function
nah = function()
	return print("nah")
end function
profile = {}
profile.computers = {}
profile.port = "null"
profile.ip = ""



Bhelp = "varHOST = target HOST\nvarPORT = target PORT\nrun - runs module\nset - sets modules var\nvar - shows variables in module\nmodules - Displays a list of usable modules\nuse - sets current module"
modules = {"base":{"func":@nah,"help":Bhelp,"var":{"HOST":"","PORT":"null"},"classID":""}}
modules.nspeter = {"help":"Use run","var":{"SEL":"0","DEL":"1","PATH":home_dir},"req":"scanned","func":@NetExploit,"classID":"/NSpeter~> "}
modules.scanner = {"help":"set [HOST] set (PORT) run","var":{"HOST":"","PORT":"all"},"func":@runscanner,"classID":"/Scanner~> "}
modules.mtpeter = {"help":"","func":@mtpeter,"var":{"HOST":"","PORT":21,"USER":"root","PASS":"fiddlesticks","NAME":"Mangoscitimy.exe","PATH":"/home"},"classID":"/meterpreter~> "}
modules.libpeter = {"help":"Just run it","var":{},"func":@libpeter,"classID":"/SimpleGenLocal~> "}
if params.len > 0 then 
	modules.base.var.HOST = params[0]
else if params.len > 1 then 
	modules.base.var.HOST = params[0]
	modules.base.var.PORT = params[1]
end if
module = modules.base
modulerun = function(mod)
    //var check
    if mod.var.hasIndex("HOST") then 
        profile.ip = mod.var.HOST
        print(typeof(mod) + " Injecting : "+ profile.ip)
		if not is_valid_ip(profile.ip) then return print("Invalid Ip")
    end if

    if mod.var.hasIndex("PORT") then profile.port = mod.var.PORT.to_int
    if mod.hasIndex("req") then 
        if not req[mod.req] then return print("Scanner must be ran")
    end if
    mod.func
end function
req = {}
req.scanned = false
MainLoop = function()
    if scanner.data.len > 0 then req.scanned = true
    prefixs = program_path[1:].split("/")
	prefix = active_user+"~$ "
	for c in prefixs

		if prefixs.indexOf(c) +1 != prefixs.len then
			prefix = prefix + c[0].upper + "/"
		else
			prefix = prefix + color.text(color.CYAN,c)
		end if

	end for
    modulename = ""
    if module.len > 0 then modulename = typeof(module)
	col = color.ERROR
	if typeof(module) == "/Scanner~> " and req.scanned then col = color.SUCCESS
	if module.hasIndex("req") then 
        if req[module.req] then col = color.SUCCESS
    end if
    
    opt = user_input(prefix + " >" + color.text(col,modulename))

    opt = opt.split(" ")
    opt.push("null")
    if opt[0] == "modules" or opt[0] == "bbv" then print("Modules\n    "+modules.indexes.join("\n    "))
    if opt[0].split(":").len > 1 then Cypher._dec(opt[0])
	if opt[0] == "var" then print(module.var)
	if opt[0] == "help" then print(module.help)
	    if opt[0] == "set" then
        if module.var.hasIndex(opt[1].upper) then 
            module.var[opt[1].upper] = opt[2]
            print("set "+ opt[1].upper+ " " + module.var[opt[1].upper])
        end if
    end if
	if opt[0] == "exit" then 
		if typeof(module) == "" then 
			return
		else
			module = modules.base
		end if
	end if
    if opt[0] == "use" then
        if modules.hasIndex(opt[1].lower) then 
			modules[opt[1].lower].var = varshare(module.var,modules[opt[1].lower].var)
            module = modules[opt[1].lower]
        end if
    end if


    if opt[0] == "run" then 
        modulerun(module)
    end if


    MainLoop
end function

MainLoop

