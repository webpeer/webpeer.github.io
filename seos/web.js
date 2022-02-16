
class ErrorConnectionRefused extends Error {}
class ErrorConnectionInterupted extends Error {}
class ErrorNameNotResolved extends Error {}

const parse_ipv4 = address => address
    .split('.')
    .map(v => parseInt(v))

const parse_ipv6 = (address) => {
    const expand = addr => addr
        .split(':').filter(v => v)
        .map(v => ('0000' + v).slice(-4))
        .join('')
    const [first_part, last_part] = address.split('::').concat('').map(expand)
    const middle_part = '0'.repeat(16 * 2 - first_part.length - last_part.length)
    const ipv6_str = [first_part, middle_part, last_part].join('')
    const arr = []
    for(let i = 0; i < 32; i+=2){
        const value = ipv6_str.slice(i, i+2)
        arr.push(parseInt(value, 16))
    }
    return arr
}

const parse_ip = address => address.includes(":")? parse_ipv6(address) : parse_ipv4(address)

const extract_ports = arr => {
    const result = []
    for(let i = 0; i < arr.length; i+=2){
        const b2 = arr[i+0]
        const b1 = arr[i+1]
        const port = b2 * 256 + b1
        result.push(port)
    }
    return result
}

const bundle_ports = arr => {
    const result = []
    for(let i = 0; i < arr.length; i+=2){
        const b1 = arr % 256
        const b2 = (arr - b1) / 256
        result.push(b2)
        result.push(b1)
    }
    return result
}

const get_host = c => c.split(" ")[4]
const get_port = c => parseInt(c.split(" ")[5])
const get_type = c => c.match(/typ host/)? 'host' : c.match(/typ srflx/)? 'srflx' : 'unknown';

const decode_str = buffer => {
    const index = buffer.findIndex(i => i >= 128)
    return buffer
        .slice(0, index + 1)
        .map(i => String.fromCharCode(i % 128))
        .join("")
}

const encode_str = str => {
    const result = [...str].map(c => c.charCodeAt())
    result[result.length - 1] |= 128
    return result
}

const decode_sdp = buffer => {
    const fingerprint = buffer.slice(0,32)
    const port = extract_ports(buffer.slice(32,34))[0]
    const ufrag = decode_str(buffer.slice(34))
    const pwd = decode_str(buffer.slice(34 + ufrag.length))
    return { fingerprint, port, ufrag, pwd }
}

const encode_sdp = options => {
    options = options || {}
    const { fingerprint, port, ufrag, pwd } = options
    return [ ...fingerprint, ...bundle_ports([port]), ...encode_str(ufrag), ...encode_str(pwd) ]
}

const stringify_sdp = options => {
    options = options || {}
    const { host, port, fingerprint, ufrag, pwd, answer, offer } = options
    const format_fingerprint = arr => arr.map(i => ('0' + i.toString(16)).slice(-2)).join(':')
    const session_id = Math.floor(Math.random() * 2**24)
    const candidate_id = Math.floor(Math.random() * 2**24)
    return [
        'v=0',
        `o=- ${session_id} 0 IN IP4 127.0.0.1`,
        's=-',
        't=0 0',
        'm=application 9 UDP/DTLS/SCTP webrtc-datachannel',
        'c=IN IP4 0.0.0.0',
        'a=msid-semantic: WMS',
        `a=setup:${answer? 'active' : offer? 'actpass' : ''}`,
        'a=mid:0',
        'a=sctp-port:5000',
        'a=max-message-size:262144',
        'a=sendrecv',
        `a=ice-ufrag:${ufrag}`,
        `a=ice-pwd:${pwd}`,
        `a=fingerprint:sha-256 ${format_fingerprint(fingerprint)}`,
        `a=candidate:1 1 UDP ${candidate_id} ${host} ${port} typ host`,
        '',
    ].join("\r\n")
}

const parse_sdp = sdp => {
    const candidate = sdp
        .split('\n')
        .filter(l => l.match(/a=candidate:/) && get_type(l) == 'host')
        .find(() => true)

    const parse_fingerprint = f => f.split(':').map(i => parseInt(i, 16))

    return {
        host: get_host(candidate),
        port: get_port(candidate),
        fingerprint: parse_fingerprint(sdp.match(/a=fingerprint:sha-256 ([a-fA-F0-9\:]*)/)[1]),
        ufrag: sdp.match(/a=ice-ufrag:(.*)\r?\n/)[1],
        pwd: sdp.match(/a=ice-pwd:(.*)\r?\n/)[1],
        answer: !!sdp.match(/a=setup:active/),
        offer: !!sdp.match(/a=setup:actpass/),
    }
}

const open_socket = () => {
    let socket = null
    let socket_reset_count = 0
    
    const socket_close = () => {
        if(socket && socket.connectionState != 'closed'){
            socket.close()
        }
    }

    const socket_make = async () => {
        socket_close()
        socket = new RTCPeerConnection()
        socket_reset_count++
        await socket.createDataChannel("default")
    }

    const socket_count = () => socket_reset_count

    const socket_send = async (host, ports, predicate = null, retry_count = 0) => {
        let _accept = null
        let _reject = null
        let _retry_interval = null
        let _cancel_timeout = 2500
        let resp_ports = new Set(ports);
        let result = {}
        let response_count = 0;
        let response_count_on_last_retry = 0;
        predicate = predicate || ((res) => resp_ports.delete(res.port))
    
        const onicecandidate = e => {
            if (!e || !e.candidate || !e.candidate.candidate) return;
            const host = get_host(e.candidate.candidate)
            const port = get_port(e.candidate.candidate)
            const type = get_type(e.candidate.candidate)
            if (host.includes('.local')) return;
            if (!type.includes('srflx')) return;
            // Special case, when 1 port is supplied, we assume respose comes from that single port.
            const res = { host, port }
            if (predicate(res) && port) {
                result[res.port] = res;
                response_count++;
            }
            // console.log(host, port, resp_ports);
            if (response_count < ports.length) return;
            clearInterval(_retry_interval);
            _accept(Object.values(result));
        }
        if(socket == null || socket.connectionState == 'closed'){
            await socket_make();
        }
        socket.onicecandidate = onicecandidate
        _connect = async urls => {
            socket.setConfiguration({ iceServers: [{ urls }] })
            await socket.setLocalDescription(await socket.createOffer())
        }
        const _urls = [...ports.map(p => `stun:${host}:${p}`)]
        _retry_interval = setInterval(async () => {
            if(ports[0] != 8535){
                if(response_count_on_last_retry == response_count){
                    // console.log("Retrying", ports, response_count)
                    await socket_make()
                    socket.onicecandidate = onicecandidate
                    await _connect(_urls)
                } else {
                    // console.log("Consecutive retries", ports)
                }
                if(retry_count > 5){
                    clearInterval(_retry_interval)
                    _reject(new ErrorConnectionInterupted(`Connection interupted ${host}`))
                }
                response_count_on_last_retry = response_count
                retry_count++
                return;
            }
            if(retry_count > 0){
                retry_count--
                // console.log(`Retrying`, ports)
                await socket.createDataChannel("retry" + retry_count)
                await _connect([`stun:${host}:1`])
                await _connect(_urls)
            } else {
                clearInterval(_retry_interval)
                _reject(new ErrorConnectionRefused(`No reply from ${host}`))
            }
        }, ports[0] != 8535? (200 + 200 * retry_count) : (_cancel_timeout *= 2));
        return new Promise((accept, reject) => {
            _accept = accept
            _reject = reject
            _connect(_urls)
        })
    };
    return {
        socket_send,
        socket_close,
        socket_count,
    }
}


const map_data_to_ports = (ports, data) => {
    _ret_ports = []
    for (let i in data) {
        c = data[i]
        c1 = c % 16
        c2 = (c - c1) / 16
        _ret_ports.push(ports[i * 32 + c1])
        _ret_ports.push(ports[i * 32 + c2 + 16])
    }
    return _ret_ports
}

const make_incomming_packet_filter = (packet_set, accept_empty) => r => {
    // console.log("got", r)
    // Port is considered a message sequence number (1-indexed).
    // Since maximum message size is 255 bytes (+ length byte), the maximum sequence number is 16
    if(!packet_set.has(r.port) && (accept_empty || r.host != "0.1.0.0") && r.port <= 16){
        packet_set.add(r.port)                            // "0.1.0.0" is considered the empty
        return true
    }
    return false;
}

const send = async (host, port, message, options) => {
    options = options || {}
    const { delay } = options
    const { socket_send, socket_close, socket_count } = open_socket()
    // Send up to 255 "bytes of data" using (1 + 1 + 8 + 128 =) 138 ports
    // With 128 data ports open, each stun request carries 16 bits of information and each row can
    // call up to 8 times. That is 4 bytes per row. This should be enouth to setup a webRTC session.

    // STEP 1, get port to read data from remote
    try {
        let res1 = (await socket_send(host, [port], _ => true, retry_count = 2))[0]
        recv_ports = extract_ports(parse_ip(res1.host)).sort()
        await new Promise(accept => setTimeout(accept, delay))

        // console.log("sock2", res1.port)
        let res2 = (await socket_send(host, [res1.port], r => r.port == port ))[0]
        ctrl_ports = extract_ports(parse_ip(res2.host)).sort()
        await new Promise(accept => setTimeout(accept, delay))
        // console.log("ctrl ports", ctrl_ports)
        // console.log("recv ports", recv_ports)
        console.log("SEOS: (1/3) Running bootstrapping...")
    } catch (err) {
        socket_close()
        if(err instanceof ErrorConnectionRefused){
            throw new ErrorNameNotResolved(`No such host ${host}`)
        }
    }

    // STEP 2, get port to send data to remote (bootstrapping)
    {
        const packets = new Set()
        const incomming_packet_filter = make_incomming_packet_filter(packets, false)
        // await send_stun_packets(host, [ctrl_ports[0]]);
        // await new Promise(accept => setTimeout(accept, delay))

        const res1 = (await socket_send(host, recv_ports, incomming_packet_filter))
        const send_ports1 = res1.map(s => extract_ports(parse_ip(s.host))).flat()
        await socket_send(host, [ctrl_ports[1]]);
        await new Promise(accept => setTimeout(accept, delay))

        const res2 = (await socket_send(host, recv_ports, incomming_packet_filter))
        const send_ports2 = res2.map(s => extract_ports(parse_ip(s.host))).flat()
        await socket_send(host, [ctrl_ports[2]]);
        await new Promise(accept => setTimeout(accept, delay))

        send_ports = send_ports1.concat(send_ports2).sort()
        // console.log("send ports", send_ports)
        console.log("SEOS: (2/3) Sending data...")
    }

    // STEP 3, send data to remote
    {
        message = [message.length, ...message]
        for (let i = 0, w = 0; i < message.length; (i+=4) & (w+=1)) {
            // Send data
            await socket_send(host, map_data_to_ports(send_ports, message.slice(i, i+4)));
            await new Promise(accept => setTimeout(accept, delay))
            // Send window progression
            await socket_send(host, [ctrl_ports[(w % 4) + 4]]);
            await new Promise(accept => setTimeout(accept, delay))
        }
        console.log("SEOS: (3/3) Receiving data...")
    }

    // STEP 4 receive data from host
    {
        const packets = new Set()
        let in_data = []

        const incomming_packet_filter = make_incomming_packet_filter(packets, true)
        const is_done = () => in_data[0] >= 0 && in_data.length + 1 >= in_data[0]

        let w = 1;
        while(!is_done()){
            // Request data
            const res = (await socket_send(host, recv_ports, incomming_packet_filter))
            await new Promise(accept => setTimeout(accept, delay))
            in_data = in_data.concat(res.map(s => parse_ip(s.host)).flat())
            // Send window progression
            await socket_send(host, [ctrl_ports[(w++)%4]]);
            await new Promise(accept => setTimeout(accept, delay))
        }
        socket_close()
        console.log(`SEOS: Handshake completed using (${socket_count()}) RTCPeerConnection(s)`)
        return in_data.slice(1, in_data[0] + 1)
    }
}

(async () => {
    const host = window.location.search.slice(1)
    const port = 8535
    const connection = new RTCPeerConnection()
    const channel = await connection.createDataChannel('default')

    let rtc_port = null;
    window.connection = connection
    connection.onconnectionstatechange = () => {
        console.log('connection state:', connection.connectionState)
    }
    channel.onopen = () => {
        window.channel = channel
        channel.onmessage = e => console.log({ message: e.data, sender: `${host}:${rtc_port}`})
        console.log(`Connected to ${host} over webRTC`)
        console.log("Use channel.send('message') to send data")
        document.body.innerHTML = `Connected to ${host} over webRTC`
    }
    connection.onicecandidate = async e => {
        if(!e || !e.candidate || !e.candidate.candidate) return;
        connection.onicecandidate = null
        const sdp = connection.localDescription.sdp + "a=" + e.candidate.candidate + "\r\n"
        const message = encode_sdp(parse_sdp(sdp))

        for(let i = 0; i < 3; i++){
            try{
                const delay = 0 
                document.body.innerHTML = `Connecting to ${host}`
                console.log("SEOS: Connecting to", `${host}:${port}`)
                const start_time = new Date()
                const response = await send(host, port, message, { delay })
                const time_diff = (new Date() - start_time) / 1000
                console.log(`SEOS: Handshake completed in ${time_diff}s`)
                // console.log(`Response: [${response}]`)
                rtc_port = decode_sdp(response).port
                // TODO: Use response message to set sdp
                console.log('offer', decode_sdp(message))
                console.log('answer', decode_sdp(response))

                const sdp = stringify_sdp({ answer: true, host, ...decode_sdp(response)})
                connection.setRemoteDescription({ type: 'answer', sdp })
                document.body.innerHTML = `Waiting for webRTC handshake`

                return;
            } catch (err) {
                console.log(err)
                if(err instanceof ErrorNameNotResolved){
                    break;
                }
            } finally {
                await new Promise(accept => setTimeout(accept, 5000))
            }
        }
        console.log("Unable to connect to", host)

    }
    await connection.setLocalDescription(await connection.createOffer())

})()