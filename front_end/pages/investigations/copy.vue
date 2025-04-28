<template>
    <div>
        <div className="flex py-6 flex-col min-h-screen bg-[#1c1e26] text-white">

            <main className="flex flex-1">
                <div className="flex-1 p-6">
                    <div className="space-y-4">
                        <h2 className="text-3xl font-bold">Investigation {{ $route.params.id }}</h2>
                        <p className="text-sm text-gray-400">2023-10-22 21:49:23</p>
                        <div className="space-y-2">
                            <p className="text-sm text-gray-400">ALERT RECEIVED</p>
                            <h3 className="text-xl font-semibold text-[#00aaff]">
                                Apache Log4j Remote Code Execution Vulnerability(92046)
                            </h3>
                            <p className="text-sm text-gray-400">vulnerability — Palo Alto NGFW</p>
                            <Link href="#" className="text-[#00aaff]">
                            Show details
                            </Link>
                        </div>
                        <div className="space-y-4">
                            <h3 className="text-2xl font-bold">Executive summary</h3>
                            <p className="text-sm">
                                The investigation was initiated following a Palo Alto NGFW alert indicating a critical
                                vulnerability
                                threat, "Apache Log4j Remote Code Execution Vulnerability(92046)", detected on
                                2023-10-23
                                01:49:23+00:00. The threat originated from an external IP address 35.90.95.119,
                                targeting the internal
                                IP 10.10.1.188. Analysis of pcap files revealed JNDI payloads, and firewall logs
                                confirmed connections
                                to an additional suspicious external IP address, 164.90.144.192. The target host was
                                found to be running
                                jar files associated with the log4j vulnerability. Two Python3 processes on the target
                                host were
                                identified as communicating with the suspicious external IP, running scripts capable of
                                remote code
                                execution, indicating a successful exploitation of the log4j vulnerability.
                            </p>
                        </div>
                        <div className="p-4 bg-[#2d2f3a] border border-red-500 rounded-md">
                            <h3 className="text-xl font-bold">Conclusion</h3>
                            <Badge variant="destructive">Malicious</Badge>
                            <p className="text-sm">
                                Immediate action should be taken to mitigate the risks and secure the affected systems.
                            </p>
                        </div>
                    </div>
                </div>
                <aside className="w-80 border-l border-gray-700">
                    <Tabs defaultValue="all">
                        <TabsList className="flex justify-between px-4 py-2 border-b border-gray-700">
                            <TabsTrigger value="chat">Chat</TabsTrigger>
                            <TabsTrigger value="actions">Actions</TabsTrigger>
                            <TabsTrigger value="all">All</TabsTrigger>
                        </TabsList>
                        <TabsContent value="chat" className="p-4" />
                        <TabsContent value="actions" className="p-4" />
                        <TabsContent value="all" className="p-4 space-y-4">
                            <div className="text-sm">
                                <p>Oct 26 2023 at 6:32 pm</p>
                                <p className="text-red-500">Palo Alto NGFW created this alert.</p>
                            </div>
                            <div className="text-sm">
                                <p>Oct 26 2023 at 6:38 pm</p>
                                <p className="text-blue-500">Dropzone completed the investigation of this alert.</p>
                            </div>
                        </TabsContent>
                    </Tabs>
                    <div className="p-4 border-t border-gray-700">
                        <form className="flex items-center">
                            <Input type="text" placeholder="Ask a question..." className="flex-1" />
                            <Button variant="ghost" className="ml-2">
                                <SendIcon className="w-5 h-5 text-gray-400" />
                            </Button>
                        </form>
                    </div>
                </aside>
            </main>
        </div>
    </div>
</template>