import requests
import pandas as pd
import time
import argparse
from datetime import datetime
from sklearn.metrics import confusion_matrix, classification_report

# --- CONFIGURATION ---
# Path to your test set (advGLUE or custom)
TEST_SET_PATH = "advglue_test.json"  # or .csv
# Flask app URL
FLASK_URL = "http://localhost:5000/"
# If you have a second model for adversarial training comparison, set its URL here
FLASK_URL_ADV = None  # e.g., "http://localhost:5001/"

# --- ARGUMENT PARSING ---
parser = argparse.ArgumentParser(description="Evaluate LLM Defense Layers")
parser.add_argument('--dataset', type=str, default='advglue_test.json', help='Path to test set (JSON or CSV)')
parser.add_argument('--url', type=str, default='http://localhost:5000/', help='Flask app URL')
parser.add_argument('--url_adv', type=str, default=None, help='Adversarially trained model URL (optional)')
args = parser.parse_args()

TEST_SET_PATH = args.dataset
FLASK_URL = args.url
FLASK_URL_ADV = args.url_adv

# --- LOAD TEST SET ---
if TEST_SET_PATH.endswith('.json'):
    df = pd.read_json(TEST_SET_PATH)
elif TEST_SET_PATH.endswith('.csv'):
    df = pd.read_csv(TEST_SET_PATH)
else:
    raise ValueError('Dataset must be .json or .csv')
if not set(['prompt', 'label']).issubset(df.columns):
    raise ValueError('Dataset must have columns: prompt, label')

results = []

def test_prompt(prompt, url=FLASK_URL):
    # Send prompt to Flask app
    resp = requests.post(url, data={"prompt": prompt}, allow_redirects=True)
    html = resp.text

    # Multi-layer trace: look for audit card and flash messages in the HTML
    blocked = "Prompt blocked" in html or "Response blocked" in html
    sanitization_block = "possible injection or invalid input" in html
    output_block = "Output filter detected" in html
    self_checker_block = "detected as possible prompt injection" in html

    # Extract self-checker status and explanation
    audit_start = html.find("LLM Self-Checker Audit")
    status = ""
    explanation = ""
    if audit_start != -1:
        status_start = html.find("audit-status", audit_start)
        status = html[status_start:status_start+50].split(">")[1].split("<")[0] if status_start != -1 else ""
        expl_start = html.find("Self-Checker Explanation:", audit_start)
        if expl_start != -1:
            explanation = html[expl_start+len("Self-Checker Explanation:"):].split("</div>")[0].strip()
    # Determine which layer blocked
    blocked_by = "none"
    if sanitization_block:
        blocked_by = "sanitization"
    elif self_checker_block:
        blocked_by = "self_checker"
    elif output_block:
        blocked_by = "output_filter"
    elif blocked:
        blocked_by = "unknown"
    return {
        "blocked": blocked,
        "sanitization_block": sanitization_block,
        "self_checker_block": self_checker_block,
        "output_block": output_block,
        "self_checker_status": status,
        "self_checker_explanation": explanation,
        "blocked_by": blocked_by,
        "html": html
    }

# --- MAIN EVALUATION LOOP ---
for row in df.itertuples():
    prompt = row.prompt
    label = row.label
    # Test with current model
    res = test_prompt(prompt, FLASK_URL)
    # If you have an adversarially trained model, test with that too
    res_adv = test_prompt(prompt, FLASK_URL_ADV) if FLASK_URL_ADV else None
    results.append({
        "prompt": prompt,
        "label": label,
        "blocked": res["blocked"],
        "sanitization_block": res["sanitization_block"],
        "self_checker_block": res["self_checker_block"],
        "output_block": res["output_block"],
        "self_checker_status": res["self_checker_status"],
        "self_checker_explanation": res["self_checker_explanation"],
        "blocked_by": res["blocked_by"],
        "blocked_adv": res_adv["blocked"] if res_adv else None,
        "self_checker_status_adv": res_adv["self_checker_status"] if res_adv else None,
        "self_checker_explanation_adv": res_adv["self_checker_explanation"] if res_adv else None,
        "blocked_by_adv": res_adv["blocked_by"] if res_adv else None,
    })
    time.sleep(0.5)  # Avoid rate limiting

results_df = pd.DataFrame(results)
timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
results_df.to_csv(f"llm_defense_eval_results_{timestamp}.csv", index=False)

# --- METRICS ---
def print_metrics(df, label_suffix=""):
    y_true = df.label
    y_pred = df.blocked.map(lambda x: 'adversarial' if x else 'benign')
    print(f"\n--- Metrics{label_suffix} ---")
    print(f"Confusion Matrix:\n{confusion_matrix(y_true, y_pred, labels=['adversarial','benign'])}")
    print(classification_report(y_true, y_pred, target_names=['adversarial','benign']))
    tp = len(df[(df.label == "adversarial") & (df.blocked)])
    tn = len(df[(df.label == "benign") & (~df.blocked)])
    fp = len(df[(df.label == "benign") & (df.blocked)])
    fn = len(df[(df.label == "adversarial") & (~df.blocked)])
    print(f"TP: {tp}, TN: {tn}, FP: {fp}, FN: {fn}")
    print(f"Accuracy: {(tp+tn)/(tp+tn+fp+fn):.2%}")
    print(f"False Positive Rate: {fp / (fp + tn):.2%}")
    print(f"False Negative Rate: {fn / (fn + tp):.2%}")

print_metrics(results_df)
if FLASK_URL_ADV:
    print_metrics(results_df.rename(columns={"blocked_adv": "blocked"}), label_suffix=" (Adversarially Trained)")

# --- LAYER-BY-LAYER ANALYSIS ---
layer_cols = ["sanitization_block", "self_checker_block", "output_block"]
for col in layer_cols:
    print(f"\n{col}: {results_df[col].sum()} prompts blocked by this layer.")

print("\n--- Blocked by Layer Breakdown ---")
print(results_df.groupby(['label','blocked_by']).size().unstack(fill_value=0))

# --- EXAMPLES ---
print("\n--- Example False Positives ---")
print(results_df[(results_df.label == "benign") & (results_df.blocked)].head(5)[["prompt", "self_checker_explanation", "blocked_by"]])
print("\n--- Example False Negatives ---")
print(results_df[(results_df.label == "adversarial") & (~results_df.blocked)].head(5)[["prompt", "self_checker_explanation", "blocked_by"]]) 