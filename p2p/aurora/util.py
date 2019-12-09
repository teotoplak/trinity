from typing import Dict, List

import scipy.stats as st
import numpy
import math

from scipy import stats as st


def _distance_expectation_matrix_markov(transition_matrix):
    transition_matrix = transition_matrix[:-1, :-1]
    return numpy.linalg.inv(numpy.identity(len(transition_matrix)) - transition_matrix)


def _distance_transition_matrix_markov(network_size, malicious_nodes_number, neighbours_response_size):
    s = (malicious_nodes_number + 1, malicious_nodes_number + 1)
    result_matrix = numpy.zeros(s)
    for row in range(malicious_nodes_number + 1):
        for column in range(malicious_nodes_number + 1):
            if row > column:
                continue
            else:
                result_matrix[row][column] = st.hypergeom(network_size,
                                                          malicious_nodes_number - row,
                                                          neighbours_response_size).pmf(column - row)
    return result_matrix


def calculate_distance(network_size, malicious_nodes_number, neighbours_response_size) -> float:
    """Calculates minimum suggested walk length over the network for Aurora algorithm"""
    transition_matrix = _distance_transition_matrix_markov(network_size, malicious_nodes_number, neighbours_response_size)
    network_size = _distance_expectation_matrix_markov(transition_matrix)
    return sum(network_size[0, :])


def assumed_malicious_node_number(network_size: int) -> int:
    """Assumed number of malicious nodes for Aurora algorithm"""
    return math.ceil(network_size / 2) - 1


def quantified_mistake(total_size, success_states_in_population, sample_size, observed_successes):
    """Function measuring suspicious behaviour of the surrounding network using hypergeometric probability
    Returns quantification of the suspicion (mistake)
    """
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
        current_key_correctness = len(correctness_list) * (average ** 3)
        if optimal_correctness is None or optimal_correctness < current_key_correctness:
            optimal_correctness = current_key_correctness
            optimal_key = key
    return optimal_key, optimal_correctness