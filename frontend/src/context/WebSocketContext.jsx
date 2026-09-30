
import React, {
  createContext,
  useContext,
  useState,
  useEffect,
  useRef,
  useCallback,
} from 'react';

const WebSocketContext = createContext(null);

export function WebSocketProvider({ children }) {
  const [events, setEvents] = useState([]);
  const [isConnected, setIsConnected] = useState(false);
  const [lastEvent, setLastEvent] = useState(null);

  // Latest Communication Security notification
  const [communicationNotification, setCommunicationNotification] =
    useState(null);

  const wsRef = useRef(null);
  const reconnectTimeout = useRef(null);

  const connect = useCallback(() => {
    try {
      const protocol =
        window.location.protocol === 'https:' ? 'wss:' : 'ws:';

      const envWs = import.meta.env.VITE_WS_URL;
      const host = window.location.host;
      const wsUrl = envWs
        ? (envWs.endsWith('/ws/security-events') ? envWs : `${envWs}/ws/security-events`)
        : `${protocol}//${host}/ws/security-events`;

      console.log('[WS] Connecting to:', wsUrl);

      const ws = new WebSocket(wsUrl);

      ws.onopen = () => {
        setIsConnected(true);
        console.log('[WS] Connected to security events stream');
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);

          // Ignore WebSocket pong messages
          if (data.type === 'pong') {
            return;
          }

          /*
           * =====================================================
           * Communication Security Notification
           * =====================================================
           */

          const isCommunicationSecurityEvent =
            data.type === 'communication_security_notification';

          if (isCommunicationSecurityEvent) {
            const communicationEvent = {
              id:
                data.event_id ||
                data.id ||
                `comm-${Date.now()}-${Math.random()
                  .toString(36)
                  .substr(2, 4)}`,

              type: data.type,

              classification:
                data.classification || 'UNKNOWN',

              risk_score:
                typeof data.risk_score === 'number'
                  ? data.risk_score
                  : 0,

              severity: (
                data.severity || 'INFO'
              ).toUpperCase(),

              policy_decision:
                data.policy_decision || 'UNKNOWN',

              notification_level:
                data.notification_level || 'NONE',

              reason:
                data.reason || 'Communication security event detected.',

              sender:
                data.sender || 'Unknown sender',

              subject:
                data.subject || 'No subject',

              human_review_required:
                Boolean(data.human_review_required),

              timestamp:
                data.timestamp || new Date().toISOString(),

              source:
                data.source || 'Communication Security Gateway',

              raw: data,
            };

            /*
             * Store the latest communication notification
             */
            setCommunicationNotification(communicationEvent);

            /*
             * Also add it to the common security events list
             */
            setLastEvent(communicationEvent);

            setEvents((prev) => [
              communicationEvent,
              ...prev,
            ].slice(0, 100));

            console.log(
              '[WS] Communication Security Notification:',
              communicationEvent
            );

            return;
          }

          /*
           * =====================================================
           * Existing Security Event Handling
           * =====================================================
           */

          const normalized = {
            id:
              data.id ||
              `evt-${Date.now()}-${Math.random()
                .toString(36)
                .substr(2, 4)}`,

            event:
              data.event ||
              data.message ||
              data.title ||
              data.description ||
              'Security Event Detected',

            source:
              data.source ||
              (data.type === 'connection'
                ? 'System'
                : data.type) ||
              'Honeypot',

            severity: (
              data.severity ||
              (data.type === 'alert'
                ? 'CRITICAL'
                : 'INFO')
            ).toUpperCase(),

            mitre:
              data.mitre ||
              data.mitre_technique ||
              data.technique_id ||
              null,

            timestamp:
              data.timestamp ||
              new Date().toISOString(),

            raw: data,
          };

          setLastEvent(normalized);

          setEvents((prev) => [
            normalized,
            ...prev,
          ].slice(0, 100));
        } catch (err) {
          console.error('[WS] Parse error:', err);
        }
      };

      ws.onclose = () => {
        setIsConnected(false);

        console.log(
          '[WS] Disconnected. Reconnecting in 3s...'
        );

        reconnectTimeout.current = setTimeout(
          connect,
          3000
        );
      };

      ws.onerror = (error) => {
        console.error('[WS] Error:', error);

        ws.close();
      };

      wsRef.current = ws;
    } catch (err) {
      console.error('[WS] Connection failed:', err);
    }
  }, []);

  useEffect(() => {
    connect();

    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }

      if (reconnectTimeout.current) {
        clearTimeout(reconnectTimeout.current);
      }
    };
  }, [connect]);

  /*
   * =========================================================
   * Send Ping
   * =========================================================
   */

  const sendPing = useCallback(() => {
    if (
      wsRef.current?.readyState ===
      WebSocket.OPEN
    ) {
      wsRef.current.send('ping');
    }
  }, []);

  /*
   * =========================================================
   * Clear Latest Communication Notification
   * =========================================================
   */

  const clearCommunicationNotification = useCallback(() => {
    setCommunicationNotification(null);
  }, []);

  /*
   * =========================================================
   * Context Value
   * =========================================================
   */

  const value = {
    // Existing functionality
    events,
    isConnected,
    lastEvent,
    sendPing,

    // Communication Security
    communicationNotification,
    clearCommunicationNotification,
  };

  return (
    <WebSocketContext.Provider value={value}>
      {children}
    </WebSocketContext.Provider>
  );
}

export function useWebSocket() {
  const context = useContext(WebSocketContext);

  if (!context) {
    throw new Error(
      'useWebSocket must be used within a WebSocketProvider'
    );
  }

  return context;
}

export default WebSocketContext;

