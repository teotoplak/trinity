import scipy.stats as st
from typing import Dict, List


def quantified_mistake(total_size, success_states_in_population, sample_size, observed_successes):
    hypergeom = st.hypergeom(total_size, success_states_in_population, sample_size)
    median = hypergeom.median()
    rounded_median = int(round(median))

    cumulative_prob_good_pick = hypergeom.cdf(rounded_median)
    cumulative_prob_bad_pick = hypergeom.cdf(sample_size) - cumulative_prob_good_pick
    cumulative_prob_seen = hypergeom.cdf(observed_successes) - cumulative_prob_good_pick
    ratio_of_likelihood_between_good_bad_choice = \
        0 if cumulative_prob_bad_pick == 0 else cumulative_prob_good_pick / cumulative_prob_bad_pick
    dampening_factor = 0 if cumulative_prob_bad_pick == 0 else cumulative_prob_seen / cumulative_prob_bad_pick

    return ratio_of_likelihood_between_good_bad_choice * dampening_factor


def optimum(m: Dict[any, List[float]]):
    """ Going over dictionary with containing correctness indicators mapped to a key
    and extracting key with an optimum value.
    """
    optimal_key = None
    optimal_correctness = None
    for key, correctness_list in m.items():
        correctness_sum = sum(correctness_list)
        if correctness_sum == 0:
            continue
        average = correctness_sum / len(correctness_list)
        current_key_correctness = len(correctness_list) * pow(average, 3)
        if optimal_correctness is None or optimal_correctness < current_key_correctness:
            optimal_correctness = current_key_correctness
            optimal_key = key
    return optimal_key, optimal_correctness


if __name__ == '__main__':
    print(quantified_mistake(100, 30, 10, 5))
