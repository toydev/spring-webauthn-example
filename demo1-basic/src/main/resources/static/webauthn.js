function bufferToBase64url(buffer) {
    const bytes = new Uint8Array(buffer);
    let str = '';
    for (const byte of bytes) {
        str += String.fromCharCode(byte);
    }
    return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function base64urlToBuffer(base64url) {
    const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    const padLen = (4 - (base64.length % 4)) % 4;
    const padded = base64 + '='.repeat(padLen);
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

function showMessage(elementId, message, isError = false) {
    const element = document.getElementById(elementId);
    element.textContent = message;
    element.className = 'message ' + (isError ? 'error' : 'success');
}

async function register() {
    const username = document.getElementById('regUsername').value;

    if (!username) {
        showMessage('regMessage', 'ユーザー名を入力してください', true);
        return;
    }

    try {
        const startResponse = await fetch('/api/webauthn/register/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username })
        });

        const options = await startResponse.json();

        if (options.error) {
            showMessage('regMessage', 'エラー: ' + options.error, true);
            return;
        }

        options.user.id = base64urlToBuffer(options.user.id);
        // challenge: リプレイ攻撃を防ぐためのワンタイムトークン（サーバが生成、認証器が署名、サーバが検証）
        options.challenge = base64urlToBuffer(options.challenge);

        if (options.excludeCredentials) {
            options.excludeCredentials = options.excludeCredentials.map(cred => ({
                ...cred,
                id: base64urlToBuffer(cred.id)
            }));
        }

        const credential = await navigator.credentials.create({ publicKey: options });

        const credentialForServer = {
            id: credential.id,
            rawId: bufferToBase64url(credential.rawId),
            response: {
                attestationObject: bufferToBase64url(credential.response.attestationObject),
                clientDataJSON: bufferToBase64url(credential.response.clientDataJSON)
            },
            type: credential.type,
            clientExtensionResults: credential.getClientExtensionResults()
        };

        const finishResponse = await fetch('/api/webauthn/register/finish', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                username,
                credential: credentialForServer
            })
        });

        const result = await finishResponse.json();

        if (result.success) {
            showMessage('regMessage', '登録が完了しました！');
        } else {
            showMessage('regMessage', 'エラー: ' + (result.error || '不明なエラー'), true);
        }
    } catch (error) {
        showMessage('regMessage', 'エラー: ' + error.message, true);
    }
}

async function authenticate() {
    const username = document.getElementById('authUsername').value;

    if (!username) {
        showMessage('authMessage', 'ユーザー名を入力してください', true);
        return;
    }

    try {
        const startResponse = await fetch('/api/webauthn/authenticate/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username })
        });

        const options = await startResponse.json();

        if (options.error) {
            showMessage('authMessage', 'エラー: ' + options.error, true);
            return;
        }

        const publicKey = options.publicKeyCredentialRequestOptions;

        // challenge: リプレイ攻撃を防ぐためのワンタイムトークン（サーバが生成、認証器が署名、サーバが検証）
        publicKey.challenge = base64urlToBuffer(publicKey.challenge);
        publicKey.allowCredentials = publicKey.allowCredentials.map(cred => {
            const cleanCred = {
                type: cred.type,
                id: base64urlToBuffer(cred.id)
            };
            // transportsが有効な配列の場合のみ追加
            if (Array.isArray(cred.transports) && cred.transports.length > 0) {
                cleanCred.transports = cred.transports;
            }
            return cleanCred;
        });

        const credential = await navigator.credentials.get({ publicKey });

        const credentialForServer = {
            id: credential.id,
            rawId: bufferToBase64url(credential.rawId),
            response: {
                authenticatorData: bufferToBase64url(credential.response.authenticatorData),
                clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
                signature: bufferToBase64url(credential.response.signature),
                userHandle: credential.response.userHandle ? bufferToBase64url(credential.response.userHandle) : null
            },
            type: credential.type,
            clientExtensionResults: credential.getClientExtensionResults()
        };

        const finishResponse = await fetch('/api/webauthn/authenticate/finish', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                username,
                credential: credentialForServer
            })
        });

        const result = await finishResponse.json();

        if (result.success) {
            // 認証成功
            showMessage('authMessage', '認証が完了しました！ユーザー: ' + result.username);
        } else {
            showMessage('authMessage', 'エラー: ' + (result.error || '不明なエラー'), true);
        }
    } catch (error) {
        showMessage('authMessage', 'エラー: ' + error.message, true);
    }
}
