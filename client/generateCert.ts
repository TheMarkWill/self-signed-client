import forge from 'node-forge'
import os from 'os';
import fs from 'fs';
import path from 'path';

/**
 * Models to create a cert
 * 
 * https://github.com/jsumners/self-cert/blob/master/index.js
 * https://github.com/MikeKovarik/selfsigned-ca/blob/master/examples/simple.js
 * https://www.npmjs.com/package/node-forge
 * https://github.com/julie-ng/nodejs-certificate-auth
 * https://knowledge.digicert.com/generalinformation/INFO2824.html
 * https://www.ibm.com/docs/en/external-auth-server/2.4.3?topic=securing-x509-extensions
 */
/**
 * openssl req \
 * 	-newkey rsa:4096 \
 *  -keyout client/mark.key \
 *  -out client/mark.csr \
 *  -nodes \
 *  -days 5000 \
 *  -subj "/CN=MARCON WILLIAN OLIVEIRA NEVES HOOPAY/C=BR/ST=MT/L=Primavera do Leste/OU=baf1fb2d-d85d-4cf7-96bf-c913e8263871"
 */


interface EntityOptions {
    commonName?: string;
    countryName?: string;
    stateName?: string;
    locality?: string;
    orgName?: string;
    shortName?: string;
}

interface OptionsCert {
    expiryOn: Date;
    bits: 2048 | 4096;
    subject?: EntityOptions;
}

class ClientCertificate {
    private rsa = forge.pki.rsa
    private pki = forge.pki

    private now = new Date()
    
    private options: OptionsCert

    private keyPair: forge.pki.KeyPair
    private cert: forge.pki.Certificate

    constructor(options: OptionsCert){
        if (!options.expiryOn) {
            options.expiryOn = new Date(
            this.now.getFullYear() + 5, this.now.getMonth() + 1, this.now.getDate()
          )
        }

        if(!options.subject) options.subject = {};

        this.options = options;

        this.generateKeyPar()
        this.generateCert()
    }

    private generateKeyPar(){
        const keys = this.rsa.generateKeyPair(this.options.bits || 4096);

        this.keyPair = keys
    }

    private generateCert(){
        const cert = this.pki.createCertificate()

        cert.publicKey = this.keyPair.publicKey;
        cert.serialNumber = '01';
        cert.validity.notBefore = this.now;
        cert.validity.notAfter = this.options.expiryOn;

        // TODO: Change to options and not default value
        const subject = [
            { name: 'commonName', value: this.options?.subject?.commonName || os.hostname() },
            { name: 'countryName', value: this.options?.subject?.countryName || 'US' },
            { name: 'stateOrProvinceName', value: this.options?.subject?.stateName || 'Georgia' },
            { name: 'localityName', value: this.options?.subject?.locality || 'Atlanta' },
            { name: 'organizationName', value: this.options?.subject?.orgName || 'None' },
            { shortName: 'OU', value: this.options?.subject?.shortName || 'example' }
        ]

        const certificateRoot = this.pki.certificateFromPem(`-----BEGIN CERTIFICATE-----
        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
        -----END CERTIFICATE-----
        `)




        cert.setSubject(subject)
        cert.setIssuer(certificateRoot.subject.attributes)

        const privateKeyRoot = this.pki.privateKeyFromPem(`-----BEGIN PRIVATE KEY-----
        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
        Y4aFYsX0QF8i0G5ciEEl19NGPOp6bDA=
        -----END PRIVATE KEY-----
        `)


        cert.setExtensions([
            {
                name: 'basicConstraints',
                cA: true
            },
            {
                name: 'keyUsage',
                keyCertSign: true,
                digitalSignature: true,
                nonRepudiation: true,
                keyEncipherment: true,
                dataEncipherment: true
            },
            {
              name: 'subjectKeyIdentifier'
          }])

        cert.sign(privateKeyRoot)

        this.cert = cert
    }

    public certToString(){
        return {
            cert: this.pki.certificateToPem(this.cert),
            rsa: {
                public: this.pki.publicKeyToPem(this.keyPair.publicKey),
                private: this.pki.privateKeyToPem(this.keyPair.privateKey),
            },
        };
    }

    public writeCertificate(folderPath: string, fileName: string){
        const certString = this.certToString();

        fs.writeFileSync(path.resolve(folderPath, `${fileName}.cert`), certString.cert);
        fs.writeFileSync(path.resolve(folderPath, `${fileName}.key`), certString.rsa.private);
        fs.writeFileSync(path.resolve(folderPath, `${fileName}.pub.key`), certString.rsa.public);
    }
}

const certificate = new ClientCertificate({
   expiryOn: new Date('2023-01-01'),
   bits: 4096,
   subject: {
       commonName: 'MARCON WILLIAN OLIVEIRA NEVES HOOPAY - NODE',
       countryName: 'BR',
       stateName: 'MT',
       locality: 'Primavera do Leste',
       shortName: 'baf1fb2d-d85d-4cf7-96bf-c913e8263871'
   } 
})

certificate.writeCertificate('./client', 'super_mark')