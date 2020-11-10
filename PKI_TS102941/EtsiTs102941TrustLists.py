class ToBeSignedCrl:
    def __init__(self, version, thisUpdate, nextUpdate, entries):
        self.version = version
        self.thisUpdate = thisUpdate
        self.nextUpdate = nextUpdate
        self.entries = entries


class CtlFormat:
    def __init__(self, version, nextUpdate, isFullCtl, ctlSequence, ctlCommands):
        self.version = version
        self.nextUpdate = nextUpdate
        self.isFullCtl = isFullCtl
        self.ctlSequence = ctlSequence
        self.ctlCommands = ctlCommands


class ToBeSignedTlmCtl(CtlFormat):
    def __init__(self, ctlCommands):
        self.ctlCommands = ctlCommands


class ToBeSignedRcaCtl(CtlFormat):
    def __init__(self, ctlCommands):
        self.ctlCommands = ctlCommands


class FullCtl(CtlFormat):
    def __init__(self, ctlCommands, isFullCtl=True):
        self.isFullCtl = isFullCtl
        self.ctlCommands = ctlCommands


class DeltaCtl(CtlFormat):
    def __init__(self, isFullCtl=False):
        self.isFullCtl = isFullCtl


class CtlCommand:
    def __init__(self, add=None, delete=None):
        self.add = add
        self.delete = delete


class CtlEntry:
    def __init__(self, rca=None, ea=None, aa=None, dc=None, tlm=None):
        self.rca = rca
        self.ea = ea
        self.aa = aa
        self.dc = dc
        self.tlm = tlm


class CtlDelete:
    def __init__(self, cert=None, dc=None):
        self.cert = cert
        self.dc = dc


class TlmEntry:
    def __init__(self, selfSignedTLMCertificate, accesPoint, linkTLMCertificate=None):
        self.selfSignedTLMCertificate = selfSignedTLMCertificate
        self.linkTLMCertificate = linkTLMCertificate
        self.accesPoint = accesPoint


class RootCaEntry:
    def __init__(self, selfSignedRootCa, linkRootCaCertificate=None):
        self.selfSignedRootCa = selfSignedRootCa
        self.linkRootCaCertificate = linkRootCaCertificate


class EaEntry:
    def __init__(self, eaCertificate, aaAccessPoint, itsAccessPoint=None):
        self.eaCertificate = eaCertificate
        self.aaAccessPoint = aaAccessPoint
        self.itsAccessPoint = itsAccessPoint


class AaEntry:
    def __init__(self, aaCertificate, accessPoint):
        self.aaCertificate = aaCertificate
        self.accessPoint = accessPoint


class DcEntry:
    def __init__(self, url, cert):
        self.url = url
        self.cert = cert


