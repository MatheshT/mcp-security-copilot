from app.orchestrator import SecurityCopilotOrchestrator

# Create the copilot object
copilot = SecurityCopilotOrchestrator()

# Run investigation
result = copilot.analyze_query("Investigate Alert 101")

# Print JSON report
print(result["report_json"])

# Save HTML report
with open("report.html", "w", encoding="utf-8") as f:
    f.write(result["report_html"])

print("\n✅ Report generated successfully!")
print("Open report.html in your browser.")