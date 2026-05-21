from fastapi import APIRouter

from backend.app.services.attack_data import attack_data

router = APIRouter()


@router.get("/technique/{technique_id}")
def get_technique(
    technique_id: str
):

    technique = attack_data.get_object_by_attack_id(
        technique_id,
        "attack-pattern"
    )

    if not technique:

        return {
            "message":
            "Technique not found"
        }

    kill_chain_phases = technique.get(
        "kill_chain_phases",
        []
    )

    tactics = [
        phase.get("phase_name")
        for phase in kill_chain_phases
    ]

    return {
        "id": technique_id,
        "name": technique.get("name"),
        "description": technique.get("description"),
        "tactics": tactics
    }

@router.get("/top-techniques/details")
def get_top_techniques_details():

    technique_ids = [
        "T1110",
        "T1046",
        "T1021",
        "T1059"
    ]

    enriched_techniques = []

    for technique_id in technique_ids:

        technique = attack_data.get_object_by_attack_id(
            technique_id,
            "attack-pattern"
        )

        if not technique:
            continue

        kill_chain_phases = technique.get(
            "kill_chain_phases",
            []
        )

        tactics = [
            phase.get("phase_name")
            for phase in kill_chain_phases
        ]

        enriched_techniques.append({
            "id": technique_id,
            "name": technique.get("name"),
            "tactics": tactics
        })

    return {
        "count": len(enriched_techniques),
        "results": enriched_techniques
    }