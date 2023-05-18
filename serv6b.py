from twisted.conch import recvline, avatar
from twisted.conch.interfaces import IConchUser, ISession
from twisted.cred.checkers import ICredentialsChecker
from twisted.cred.credentials import IUsernamePassword
from twisted.conch.ssh import factory, keys, session
from twisted.conch.insults import insults
from twisted.cred import portal, checkers
from twisted.internet import reactor
from zope.interface import implementer

from datetime import datetime
import time
def dump(obj):
    pass

def prot2addr(protocol):
    peer = protocol.getPeer()
    return str(peer.address.host) +":"+ str(peer.address.port)

def writeline(line,peer=None,user=None):
    f = open('logfile.log', 'a')
    #f.write(line + '\n')
    epoch_time = int(time.time())
    s = str(epoch_time)+"\t"+str(peer)+"\t"+str(user)+"\t"+line
    print(s)
    f.write(s+"\n")
    f.close()

def gettime():
    a= datetime.utcnow().strftime("%a %b")
    d = datetime.utcnow().strftime("%d")
    c = datetime.utcnow().strftime("%H:%M:%S UTC %Y")
    if d[0] == '0':
        d = ' '+d[1]
    return "System information as of "+a + " " + d + ' ' + c
# SSHTransportBase(protocol.Protocol):
class SSHDemoProtocol(recvline.HistoricRecvLine):
    def __init__(self, user):
       self.user = user
       print("SSHDEMOPRotocol init, peer=")
       print("dumping SSHDemoProtocol")
       dump(self)

    def writeline(self,msg):
        writeline(msg,peer=self.user.peer,user=self.user.username)
       
    def dataReceived(self,data):
        print("Data rec:",data)
        return
    def connectionMade(self):
        recvline.HistoricRecvLine.connectionMade(self)
        self.writeline("connectionMade")
        if self.user.cmd:
            self.writeline("user provided command" + str(self.user.cmd))
            self.do_barf()
        else:
            self.conMade()
    def conMade(self):

        msg="""Welcome to Ubuntu 22.10 (GNU/Linux 5.19.0-23-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

   """
        msg+=gettime()
        msg+="""
   System load:  0.00390625        Users logged in:       1
   Usage of /:   26.1% of 9.52GB   IPv4 address for eth0: 0.0.0.0 
   Memory usage: 41%               IPv4 address for eth0: 10.10.0.10
   Swap usage:   0%                IPv4 address for eth1: 10.115.0.8
   Processes:    91

104 updates can be applied immediately.
75 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable

New release '23.04' available.
Run 'do-release-upgrade' to upgrade to it.


Last login: Sun May  7 23:31:10 2023 from 162.234.180.163"""
        msg = "Last login: Sun May  7 23:31:10 2023 from 162.234.180.163"
        self.terminal.write(msg)
        self.writeline("showedBannerShort")
        self.terminal.nextLine()
        #self.do_help()
        self.showPrompt()

    def showPrompt(self):
        self.terminal.write(self.user.username)
        self.terminal.write('@ubuntu-s-1vcpu-512mb-10gb-nyc1-01:~# ')
 
    def getCommandFunc(self, cmd):
        return getattr(self, 'do_' + cmd, None)
 
    def lineReceived(self, line):
        line = line.decode().strip()
        
        if line:
            print(line)
            self.writeline("REC>>"+line)
            ##f = open('logfile.log', 'a')
            #f.write(line + '\n')
            #f.close()
            #cmdAndArgs = line.split()
            #cmd = cmdAndArgs[0]
            #args = cmdAndArgs[1:]
            #func = self.getCommandFunc(cmd)
            #if func:
            #    try:
            #        func(*args)
            #    except Exception as e:
            #        self.terminal.write("Error: %s" % e)
            #        self.terminal.nextLine()
            #else:
            #    self.terminal.write("No such command.")
            #self.terminal.nextLine()
            #self.terminal.loseConnection()
            #self.showPrompt()
            if line == "sh" or line == "shell":
                self.writeline("Showing # Prompt")
                #self.terminal.nextLine()
                self.terminal.write("# ")
            elif line == "enable":
                self.do_enable()
            else:
                self.do_quit()
    def do_help(self):
        publicMethods = filter(
            lambda funcname: funcname.startswith('do_'), dir(self))
        commands = [cmd.replace('do_', '', 1) for cmd in publicMethods]
        self.terminal.write("Commands: " + " ".join(commands))
        self.terminal.nextLine()
 
    def do_echo(self, *args):
        self.terminal.write(" ".join(args))
        self.terminal.nextLine()
 
    def do_whoami(self):
        self.terminal.write(self.user.username)
        self.terminal.nextLine()
 
    def do_quit(self):
        self.writeline("do_quit")
        self.terminal.nextLine()
        self.terminal.loseConnection()
    def do_enable(self):
        data = """enable .
enable :
enable [
enable alias
enable bg
enable bind
enable break
enable builtin
enable caller
enable cd
enable command
enable compgen
enable complete
enable compopt
enable continue
enable declare
enable dirs
enable disown
enable echo
enable enable
enable eval
enable exec
enable exit
enable export
enable false
enable fc
enable fg
enable getopts
enable hash
enable help
enable history
enable jobs
enable kill
enable let
enable local
enable logout
enable mapfile
enable popd
enable printf
enable pushd
enable pwd
enable read
enable readarray
enable readonly
enable return
enable set
enable shift
enable shopt
enable source
enable suspend
enable test
enable times
enable trap
enable true
enable type
enable typeset
enable ulimit
enable umask
enable unalias
enable unset
enable wait""".strip()
        self.terminal.write(data)
        self.terminal.nextLine()
        self.writeline("showingEnable")
        self.terminal.write("# ")
    def do_barf(self):
        self.do_quit()
        #self.terminal.loseConnection()
    def do_clear(self):
        self.terminal.reset()
@implementer(ISession)
class SSHDemoAvatar(avatar.ConchUser):
     
    def __init__(self, username):
        avatar.ConchUser.__init__(self)
        self.username = username
        self.channelLookup.update({b'session': session.SSHSession})
        self.cmd = None 
 
    def openShell(self, protocol):

        self.peer = prot2addr(protocol)
        writeline("openShell",peer=self.peer,user=self.username)

        serverProtocol = insults.ServerProtocol(SSHDemoProtocol, self)
        serverProtocol.makeConnection(protocol)
        protocol.makeConnection(session.wrapProtocol(serverProtocol))

    def getPty(self, terminal, windowSize, attrs):
        return None
 
 
    def execCommand(self, protocol, cmd):
        addr=prot2addr(protocol)
        writeline("execCommand=>>"+str(cmd),peer=addr,user=self.username)
        #print("wanted command",cmd,"from",protocol.getPeer())
        if "uname" in str(cmd):
            protocol.write(b'Linux ubuntu-s-1vcpu-512mb-10gb-nyc1-01 5.19.0-23-generic #24-Ubuntu SMP PREEMPT_DYNAMIC Fri Oct 14 15:39:57 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux')
        #protocol.session.conn.sendEOF(protocol.session.conn)
        self.cmd = "quit"
        self.openShell(protocol)
        if False and cmd == b'uname -a':
            print("running uname command")
            protocol.write('Linux ubuntu-s-1vcpu-512mb-10gb-nyc1-01 5.19.0-23-generic #24-Ubuntu SMP PREEMPT_DYNAMIC Fri Oct 14 15:39:57 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux')
            protocol.session.conn.sendEOF(protocol.session.conn)
            protocol.session.conn.sendClose()
            #protocol.session.conn.ssh_CHANNEL_CLOSE(protocol.session.conn)
            #dump(protocol.session)
            #for x in dir(protocol.session.conn):
            #@    print("\t\t",x)
            #protocol.session.conn.closed() 
            #print("wanted command",cmd,"from",protocol.getPeer())
            #pass
            #raise NotImplementedError()  
            return 
        else:
            #raise NotImplementedError()
            return
    def eofReceived(self):
        
        writeline("eofReceived",user=self.username)
        pass
    def closed(self):
        pass
 
@implementer(portal.IRealm)
class SSHDemoRealm(object):
     
    def requestAvatar(self, avatarId, mind, *interfaces):
        print("avatar requested")
        if IConchUser in interfaces:
            return interfaces[0], SSHDemoAvatar(avatarId), lambda: None
        else:
            raise NotImplementedError("No supported interfaces found.")

def getRSAKeys():
    with open(r'foo', "rb") as privateBlobFile:
        privateBlob = privateBlobFile.read()
        privateKey = keys.Key.fromString(data=privateBlob)

    with open(r'foo.pub', "rb") as publicBlobFile:
        publicBlob = publicBlobFile.read()
        publicKey = keys.Key.fromString(data=publicBlob)

    return publicKey, privateKey


class PasswordChecker(object):
    """
    A very simple username/password checker which authenticates anyone whose
    password matches their username and rejects all others.
    """
    credentialInterfaces = (IUsernamePassword,)
    #implements(ICredentialsChecker)


    def requestAvatarId(self, creds):

        #if creds.username == creds.password:
        writeline(str(("login",creds.username,creds.password)))
        if True:
            return creds.username + b':' + creds.password
            return defer.succeed(creds.username)
        #return defer.fail(UnauthorizedLogin("Invalid username/password pair"))

if __name__ == "__main__":
    sshFactory = factory.SSHFactory()
    print(type(sshFactory))
    sshFactory.protocol.ourVersionString = b'SSH-2.0-OpenSSH_9.0p1 Ubuntu-1ubuntu7'
    ocm = sshFactory.protocol.connectionMade
    def connectionMade(sel):

        addr = prot2addr(sel)
        writeline("Connection",peer=addr)

        ocm(sel)
    sshFactory.protocol.connectionMade = connectionMade
    sshFactory.portal = portal.Portal(SSHDemoRealm())
 
users = {'admin': b'aaa', 'guest': b'bbb'}
sshFactory.portal.registerChecker(PasswordChecker())
#sshFactory.portal.registerChecker(
#    checkers.InMemoryUsernamePasswordDatabaseDontUse(**users))
pubKey, privKey = getRSAKeys()
sshFactory.publicKeys = {b'ssh-rsa': pubKey}
sshFactory.privateKeys = {b'ssh-rsa': privKey}
reactor.listenTCP(22, sshFactory)
reactor.run()
