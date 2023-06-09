from twisted.conch import recvline, avatar
from twisted.conch.interfaces import IConchUser, ISession, IUsernamePassword, ICredentialsChecker
from twisted.conch.ssh import factory, keys, session
from twisted.conch.insults import insults
from twisted.cred import portal, checkers
from twisted.internet import reactor
from zope.interface import implementer


class PasswordChecker(object):
    """
    A very simple username/password checker which authenticates anyone whose
    password matches their username and rejects all others.
    """
    credentialInterfaces = (IUsernamePassword,)
    implements(ICredentialsChecker)


    def requestAvatarId(self, creds):
        if creds.username == creds.password:
            return defer.succeed(creds.username)
        return defer.fail(UnauthorizedLogin("Invalid username/password pair"))

class SSHDemoProtocol(recvline.HistoricRecvLine):
    def __init__(self, user):
       self.user = user
 
    def connectionMade(self):
        recvline.HistoricRecvLine.connectionMade(self)
        self.terminal.write("Welcome to my test SSH server.")
        self.terminal.nextLine()
        self.do_help()
        self.showPrompt()
 
    def showPrompt(self):
        self.terminal.write(f'$ ')
 
    def getCommandFunc(self, cmd):
        return getattr(self, 'do_' + cmd, None)
 
    def lineReceived(self, line):
        line = line.decode().strip()
        if line:
            print(line)
            f = open('logfile.log', 'w')
            f.write(line + '\n')
            f.close
            cmdAndArgs = line.split()
            cmd = cmdAndArgs[0]
            args = cmdAndArgs[1:]
            func = self.getCommandFunc(cmd)
            if func:
                try:
                    func(*args)
                except Exception as e:
                    self.terminal.write("Error: %s" % e)
                    self.terminal.nextLine()
            else:
                self.terminal.write("No such command.")
                self.terminal.nextLine()
        self.showPrompt()
 
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
 
 
    def getPty(self, terminal, windowSize, attrs):
        return None
 
 
    def execCommand(self, protocol, cmd):
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
 
if __name__ == "__main__":
    sshFactory = factory.SSHFactory()
    sshFactory.portal = portal.Portal(SSHDemoRealm())
 
users = {'admin': b'aaa', 'guest': b'bbb'}
sshFactory.portal.registerChecker(
    checkers.InMemoryUsernamePasswordDatabaseDontUse(**users))
pubKey, privKey = getRSAKeys()
sshFactory.publicKeys = {b'ssh-rsa': pubKey}
sshFactory.privateKeys = {b'ssh-rsa': privKey}
reactor.listenTCP(22222, sshFactory)
reactor.run()
