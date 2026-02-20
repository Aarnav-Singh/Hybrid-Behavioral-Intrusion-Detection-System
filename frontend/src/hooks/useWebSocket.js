import { useState, useEffect, useRef, useCallback } from 'react';

const RECONNECT_INTERVAL = 3000;

export const useWebSocket = (url) => {
    const [isConnected, setIsConnected] = useState(false);
    const [data, setData] = useState(null);
    const ws = useRef(null);
    const timer = useRef(null);

    const connect = useCallback(() => {
        try {
            ws.current = new WebSocket(url);

            ws.current.onopen = () => {
                console.log('WS Connected');
                setIsConnected(true);
                // Clear any reconnect timer if connection succeeds
                if (timer.current) {
                    clearTimeout(timer.current);
                    timer.current = null;
                }
            };

            ws.current.onmessage = (event) => {
                try {
                    const parsed = JSON.parse(event.data);
                    setData(parsed);
                } catch (e) {
                    console.error('WS Parse Error', e);
                }
            };

            ws.current.onclose = () => {
                console.log('WS Closed');
                setIsConnected(false);
                // Attempt reconnect
                timer.current = setTimeout(() => {
                    console.log('Reconnecting...');
                    connect();
                }, RECONNECT_INTERVAL);
            };

            ws.current.onerror = (error) => {
                console.error('WS Error', error);
                ws.current.close();
            };
        } catch (e) {
            console.error('WS Connection Creation Error', e);
        }
    }, [url]);

    useEffect(() => {
        connect();
        return () => {
            if (ws.current) ws.current.close();
            if (timer.current) clearTimeout(timer.current);
        };
    }, [connect]);

    const sendMessage = useCallback((msg) => {
        if (ws.current && ws.current.readyState === WebSocket.OPEN) {
            ws.current.send(JSON.stringify(msg));
        }
    }, []);

    return { isConnected, data, sendMessage };
};
