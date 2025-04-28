class Invest{
    invest_id: number;
    name: string;
    amount: number;
    date: Date;
    summary: string;
    alert_index: string;
    conclusion: string;
    constructor(invest_id: number, name: string, amount: number, date: Date, summary: string, conclusion: string, alert_index: string){
        this.invest_id = invest_id;
        this.name = name;
        this.amount = amount;
        this.date = date;
        this.summary = summary;
        this.conclusion = conclusion;
        this.alert_index = alert_index;
    }
}