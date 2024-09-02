export interface IRestClientGateway {
    get(url: string, token: string): Promise<any>;
    post(url: string, body: any): Promise<any>;
    put(url: string, body: any): Promise<any>;
    delete(url: string): Promise<any>;
}