class Invest{
    _index: string;
    id: number;
    name: string;
    amount: number;
    date: Date;
    attack_type: string;
    sip: string;
    sport: string;
    dip : string;
    dport: string;
    constructor(id: number, name: string, amount: number, date: Date, _index: string, attack_type: string, sip: string, sport: string, dip: string, dport: string){
        this.id = id;
        this.name = name;
        this.amount = amount;
        this.date = date;
        this._index = _index;
        this.attack_type = attack_type;
        this.sip = sip;
        this.sport = sport;
        this.dip = dip;
        this.dport = dport;
    }
}