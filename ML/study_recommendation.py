# Rule based - study_recommendation
def generate_recommendation(input_data):
    """
    input_data: dict with keys like 'studytime', 'failures', 'absences', 'G1', 'G2'
    Returns: str (personalized recommendation)
    """
    studytime = input_data.get("studytime", 0)
    failures = input_data.get("failures", 0)
    absences = input_data.get("absences", 0)
    G1 = input_data.get("G1", 0)
    G2 = input_data.get("G2", 0)

    # Rule-based recommendations
    if studytime < 2 and failures >= 2:
        return "Increase your study time and seek support for failed subjects."
    elif absences > 10:
        return "Try to attend classes more regularly to improve consistency."
    elif G1 < 10 or G2 < 10:
        return "Focus on early performance. Study consistently and seek feedback."
    elif G1 >= 15 and G2 >= 15:
        return "Excellent performance! Keep pushing and aim higher."
    else:
        return "You're on track. Stay consistent and manage your time wisely."
