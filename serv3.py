from twisted.conch import recvline, avatar
from twisted.conch.interfaces import IConchUser, ISession
from twisted.cred.checkers import ICredentialsChecker
from twisted.cred.credentials import IUsernamePassword
from twisted.conch.ssh import factory, keys, session
from twisted.conch.insults import insults
from twisted.cred import portal, checkers
from twisted.internet import reactor
from zope.interface import implementer

def writeline(line):
    f = open('logfile.log', 'a')
    f.write(line + '\n')
    f.close()

# SSHTransportBase(protocol.Protocol):
class SSHDemoProtocol(recvline.HistoricRecvLine):
    def __init__(self, user):
       self.user = user
 
    def connectionMade(self):
        print("conmade",type(self))
        #ip, port = self.getpeer()
        #print("ip",ip,"port",port)
        recvline.HistoricRecvLine.connectionMade(self)
        msg="""Welcome to Ubuntu 22.10 (GNU/Linux 5.19.0-23-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

   System information as of Mon May  8 00:10:15 UTC 2023
   System load:  0.00390625        Users logged in:       0
   Usage of /:   26.1% of 9.52GB   IPv4 address for eth0: 192.168.0.1
   Memory usage: 41%               IPv4 address for eth0: 10.10.0.10
   Swap usage:   0%                IPv4 address for eth1: 10.115.0.8
   Processes:    91

104 updates can be applied immediately.
75 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable

New release '23.04' available.
Run 'do-release-upgrade' to upgrade to it.


Last login: Sun May  7 23:31:10 2023 from 162.234.180.163"""
        self.terminal.write(msg)
        self.terminal.nextLine()
        #self.do_help()
        self.showPrompt()
 
    def showPrompt(self):
        #print(type(self.user))
        self.terminal.write(self.user.username)
        self.terminal.write(b'@ubuntu-s-1vcpu-512mb-10gb-nyc1-01:~# ')
 
    def getCommandFunc(self, cmd):
        return getattr(self, 'do_' + cmd, None)
 
    def lineReceived(self, line):
        line = line.decode().strip()
        if line:
            print(line)
            
            writeline(line)
            
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
        self.terminal.nextLine()
        self.terminal.loseConnection()
        #self.showPrompt()
 
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
        self.terminal.write("Thanks for playing!")
        self.terminal.nextLine()
        self.terminal.loseConnection()
 
    def do_clear(self):
        self.terminal.reset()
@implementer(ISession)
class SSHDemoAvatar(avatar.ConchUser):
     
    def __init__(self, username):
        avatar.ConchUser.__init__(self)
        self.username = username
        self.channelLookup.update({b'session': session.SSHSession})
 
 
    def openShell(self, protocol):
        serverProtocol = insults.ServerProtocol(SSHDemoProtocol, self)
        serverProtocol.makeConnection(protocol)
        protocol.makeConnection(session.wrapProtocol(serverProtocol))
        print(type(protocol))
        print(type(protocol.transport))
        print(protocol.getPeer())
        peer=str(protocol.getPeer())
        writeline(peer)
    def getPty(self, terminal, windowSize, attrs):
        return None
 
 
    def execCommand(self, protocol, cmd):
        writeline(str(cmd))
        raise NotImplementedError()
 
 
    def closed(self):
        
        pass
 
@implementer(portal.IRealm)
class SSHDemoRealm(object):
     
    def requestAvatar(self, avatarId, mind, *interfaces):
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
        print(type(self))
        #if creds.username == creds.password:
        writeline(str(("login",creds.username,creds.password)))
        if True:
            return creds.username
            return defer.succeed(creds.username)
        #return defer.fail(UnauthorizedLogin("Invalid username/password pair"))

if __name__ == "__main__":
    sshFactory = factory.SSHFactory()
    print(type(sshFactory))
    sshFactory.protocol.ourVersionString = b'SSH-2.0-OpenSSH_9.0p1 Ubuntu-1ubuntu7'
    def connectionMade(self):
        self.transport.write(self.ourVersionString + b"\r\n")
        ip, port = self.transport.socket.getpeername()
        print("Connection from",ip,port)
    #sshFactory.protocol.connectionMade = connectionMade
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
