export const protocols = ["webtty"];

export const msgInputUnknown = '0';
export const msgInput = '1';
export const msgPing = '2';
export const msgResizeTerminal = '3';
export const msgOTPInput = '4';

export const msgUnknownOutput = '0';
export const msgOutput = '1';
export const msgPong = '2';
export const msgSetWindowTitle = '3';
export const msgSetPreferences = '4';
export const msgSetReconnect = '5';
export const msgOTPRequired = '6';


export interface Terminal {
    info(): { columns: number, rows: number };
    output(data: string): void;
    showMessage(message: string, timeout: number): void;
    removeMessage(): void;
    setWindowTitle(title: string): void;
    setPreferences(value: object): void;
    onInput(callback: (input: string) => void): void;
    onResize(callback: (columns: number, rows: number) => void): void;
    reset(): void;
    deactivate(): void;
    close(): void;
}

export interface Connection {
    open(): void;
    close(): void;
    send(data: string): void;
    isOpen(): boolean;
    onOpen(callback: () => void): void;
    onReceive(callback: (data: string) => void): void;
    onClose(callback: () => void): void;
}

export interface ConnectionFactory {
    create(): Connection;
}


export class WebTTY {
    term: Terminal;
    connectionFactory: ConnectionFactory;
    args: string;
    authToken: string;
    reconnect: number;
    verifyOTP: boolean;
    otp: string;

    constructor(term: Terminal, connectionFactory: ConnectionFactory, args: string, authToken: string) {
        this.term = term;
        this.connectionFactory = connectionFactory;
        this.args = args;
        this.authToken = authToken;
        this.reconnect = -1;
        this.verifyOTP = false;
        this.otp = "";
    };

    open() {
        let connection = this.connectionFactory.create();
        let pingTimer: number;
        let reconnectTimeout: number;

        const setup = () => {
            connection.onOpen(() => {
                const termInfo = this.term.info();

                connection.send(JSON.stringify(
                    {
                        Arguments: this.args,
                        AuthToken: this.authToken,
                    }
                ));


                const resizeHandler = (columns: number, rows: number) => {
                    connection.send(
                        msgResizeTerminal + JSON.stringify(
                            {
                                columns: columns,
                                rows: rows
                            }
                        )
                    );
                };

                this.term.onResize(resizeHandler);
                resizeHandler(termInfo.columns, termInfo.rows);

                this.term.onInput(
                    (input: string) => {
                        if (this.verifyOTP) {
                            // if input is enter or escape, send the OTP
                            console.log("OTP input: " + input + "; otp: " + this.otp);
                            if (input === "\r") {
                                connection.send(msgOTPInput + this.otp);
                                this.otp = "";
                            } else if (input.length > 0) {
                                this.otp += input;
                            }
                        } else {
                            connection.send(msgInput + input);
                        }
                    }
                );

                pingTimer = window.setInterval(() => {
                    connection.send(msgPing)
                }, 30 * 1000);

            });

            connection.onReceive((data) => {
                const payload = data.slice(1);
                switch (data[0]) {
                    case msgOutput:
                        this.term.output(atob(payload));
                        break;
                    case msgPong:
                        break;
                    case msgSetWindowTitle:
                        this.term.setWindowTitle(payload);
                        break;
                    case msgSetPreferences:
                        const preferences = JSON.parse(payload);
                        this.term.setPreferences(preferences);
                        break;
                    case msgSetReconnect:
                        const autoReconnect = JSON.parse(payload);
                        console.log("Enabling reconnect: " + autoReconnect + " seconds")
                        this.reconnect = autoReconnect;
                        break;
                    case msgOTPRequired:
                        var msg = JSON.parse(atob(payload));
                        this.term.output(msg.message);
                        this.verifyOTP = msg.shouldVerify == "true";
                        break;
                }
            });

            connection.onClose(() => {
                clearInterval(pingTimer);
                this.term.deactivate();
                this.term.showMessage("Connection Closed", 0);
                if (this.reconnect > 0) {
                    reconnectTimeout = window.setTimeout(() => {
                        connection = this.connectionFactory.create();
                        this.term.reset();
                        setup();
                    }, this.reconnect * 1000);
                }
            });

            connection.open();
        }

        setup();
        return () => {
            clearTimeout(reconnectTimeout);
            connection.close();
        }
    };
}
