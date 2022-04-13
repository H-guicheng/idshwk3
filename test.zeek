global ipTable : table[addr] of set[string] = table();
event http_header(c:connection,is_orig:bool,name:string,value:string)
{
	if(c$http?$user_agent)
	{
		local user_agent=c$http$user_agent;
		local src_ip=c$id$orig_h;
		if(src_ip in ipTable)
			add(ipTable[src_ip])[user_agent];
		else
			ipTable[src_ip]=set(user_agent);
	}
}

event zeek_done()
{
	for(ip in ipTable)
	{
		if(|ipTable[ip]|>=3)
			print fmt("%s is a proxy",ip);
	}
}