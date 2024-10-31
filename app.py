from flask import Flask, jsonify
from GDPR import GDPR_Compliance_Check
from HIPPA import HIPPA_Compliance_Check
from PCIDSS import PCIDSS_Compliance_Check


app = Flask(__name__)

@app.route('/api/compliance/gdpr', methods=['GET'])
def gdpr_compliance():
    results = GDPR_Compliance_Check.run_compliance_checks()
    return jsonify(results)

@app.route('/api/compliance/hipaa', methods=['GET'])
def hipaa_compliance():
    results = HIPPA_Compliance_Check.run_compliance_checks()
    return jsonify(results)

@app.route('/api/compliance/pcidss', methods=['GET'])
def pcidss_compliance():
    results = PCIDSS_Compliance_Check.run_compliance_checks()
    return jsonify(results)

@app.route('/api/compliance/summary', methods=['GET'])
def compliance_summary():
    gdpr_results = GDPR_Compliance_Check.run_compliance_checks()
    print(f"GDPR RESULTS : {gdpr_results}")
    hippa_results = HIPPA_Compliance_Check.run_compliance_checks()
    print(f"HIPPA RESULTS : {hippa_results}")
    pcidss_results = PCIDSS_Compliance_Check.run_compliance_checks()
    print(f"PCIDSS RESULTS : {pcidss_results}")
    
    summary = {
        'gdpr': summarize_results(gdpr_results),
        'hipaa': summarize_results(hippa_results),
        'pciDss': summarize_results(pcidss_results)
    }

    return jsonify(summary)

def summarize_results(results):
    print(f"Results : \n {results}")
    passed = sum(1 for check in results if check[2] == "Passed")
    total = len(results)
    return {
        'passed': passed,
        'failed': total - passed,
        'total': total
    }

@app.route('/api/insights', methods=['GET'])
def insights():
    insights_data = compliance_summary()  # Call the get_insights function
    return jsonify(insights_data)

if __name__ == '__main__':
    app.run(debug=True)